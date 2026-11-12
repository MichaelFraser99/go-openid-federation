package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type countingStatusRetriever struct {
	testTrustMarkRetriever
	asked *atomic.Int64
}

func (r countingStatusRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	r.asked.Add(1)
	return model.Pointer("active"), nil
}

func TestServer_TrustMarkStatus_AnswersNotFoundForATrustMarkThisServerDidNotIssue(t *testing.T) {
	const issuer = "https://issuer.example.com"
	segment := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("failed to encode a segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := segment(map[string]any{"alg": "ES256", "kid": "tm", "typ": "trust-mark+jwt"})
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	claims := func(iss any) map[string]any {
		body := map[string]any{"sub": "https://leaf.example.com", "trust_mark_type": "https://tm.example.com/a", "iat": time.Now().Unix()}
		if iss != nil {
			body["iss"] = iss
		}
		return body
	}
	padded := claims(issuer)
	padding := make([]any, model.DefaultMaxStatementValues+1)
	for i := range padding {
		padding[i] = 0
	}
	padded["x_padding"] = padding

	whole := segment(claims(issuer))
	for pad := ""; len(whole)%4 != 0; pad += "x" {
		body := claims(issuer)
		body["x_pad"] = pad
		whole = segment(body)
	}

	tests := []struct {
		name   string
		mark   string
		issued bool
	}{
		{name: "a trust mark this server issued", mark: header + "." + segment(claims(issuer)) + "." + signature, issued: true},
		{name: "a trust mark this server issued, with a signature that is not checked here", mark: header + "." + segment(claims(issuer)) + ".bm90LWEtc2lnbmF0dXJl", issued: true},
		{name: "a trust mark another entity issued", mark: header + "." + segment(claims("https://other-issuer.example.com")) + "." + signature},
		{name: "a trust mark whose iss differs by a trailing slash", mark: header + "." + segment(claims(issuer+"/")) + "." + signature},
		{name: "a trust mark whose iss differs in case", mark: header + "." + segment(claims("https://ISSUER.example.com")) + "." + signature},
		{name: "a trust mark with no iss", mark: header + "." + segment(claims(nil)) + "." + signature},
		{name: "a trust mark whose iss is not a string", mark: header + "." + segment(claims(7)) + "." + signature},
		{name: "a value that is not a JWT", mark: "not-a-trust-mark"},
		{name: "two segments", mark: header + "." + segment(claims(issuer))},
		{name: "four segments", mark: header + "." + segment(claims(issuer)) + "." + signature + "." + signature},
		{name: "a payload that is not base64url", mark: header + ".!!." + signature},
		{name: "a payload this server issued followed by characters that are not base64url", mark: header + "." + whole + "!!." + signature},
		{name: "a payload that is a JSON array", mark: header + "." + segment([]any{issuer}) + "." + signature},
		{name: "a payload with more values than a statement may hold", mark: header + "." + segment(padded) + "." + signature},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			asked := &atomic.Int64{}
			var logs bytes.Buffer
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:    issuer,
				SignerConfiguration: model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
				TrustMarkRetriever:  countingStatusRetriever{asked: asked},
				Configuration:       model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			defer ts.Close()

			response, err := ts.Client().PostForm(ts.URL+"/trust-mark-status", url.Values{"trust_mark": {tc.mark}})
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if tc.issued {
				if response.StatusCode != http.StatusOK || asked.Load() != 1 {
					t.Fatalf("[8.4.2] expected a trust mark this server issued to reach the retriever and answer 200, got %d after %d lookups: %s", response.StatusCode, asked.Load(), raw)
				}
				return
			}
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("[8.4.2] expected 404 for something this server did not issue, got %d %s", response.StatusCode, raw)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if answer["error"] != model.NotFound || answer["error_description"] != "unknown trust mark" {
				t.Errorf("[8.4.2] expected not_found with the existing description, got %s", raw)
			}
			if asked.Load() != 0 {
				t.Errorf("expected the retriever not asked about a trust mark this server did not issue, got %d lookups", asked.Load())
			}
			if strings.Contains(logs.String(), `"level":"ERROR"`) {
				t.Errorf("expected a caller's value to be logged at Info only, got %s", logs.String())
			}
			if strings.Contains(logs.String(), "other-issuer") {
				t.Errorf("expected the caller's value not logged, got %s", logs.String())
			}
		})
	}
}
