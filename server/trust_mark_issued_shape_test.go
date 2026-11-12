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
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const (
	issuedMarkIssuer  = "https://issuer.example.com"
	issuedMarkSubject = "https://sub.example.com"
	issuedMarkType    = "https://tm.example.com/verified"
)

func signedTrustMark(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	token, err := jwt.New(signer, map[string]any{"kid": "tm", "typ": typ, "alg": "ES256"}, claims, jwt.Opts{Algorithm: jwa.ES256})
	if err != nil {
		t.Fatalf("failed to sign the trust mark: %v", err)
	}
	return *token
}

func issuedMarkClaims() map[string]any {
	return map[string]any{"iss": issuedMarkIssuer, "sub": issuedMarkSubject, "trust_mark_type": issuedMarkType, "iat": time.Now().Unix()}
}

func encodedSegment(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to encode a segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

type fixedTrustMarkRetriever struct {
	testTrustMarkRetriever
	issued string
}

func (r fixedTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return &r.issued, nil
}

func TestServer_TrustMark_ServesOnlyATrustMarkForTheRequestedSubjectAndType(t *testing.T) {
	const marker = "RETRIEVER-VALUE-MARKER"
	header := map[string]any{"kid": "tm", "typ": "trust-mark+jwt", "alg": "ES256"}
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	with := func(member string, value any) map[string]any {
		claims := issuedMarkClaims()
		if value == nil {
			delete(claims, member)
		} else {
			claims[member] = value
		}
		return claims
	}
	headerWith := func(member string, value any) map[string]any {
		changed := map[string]any{}
		for k, v := range header {
			changed[k] = v
		}
		if value == nil {
			delete(changed, member)
		} else {
			changed[member] = value
		}
		return changed
	}

	tests := []struct {
		name  string
		mark  func(t *testing.T) string
		cause string
	}{
		{name: "a signed trust mark for the subject and type", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", issuedMarkClaims())
		}},
		{name: "a signed trust mark whose typ carries the application/ prefix", mark: func(t *testing.T) string {
			return signedTrustMark(t, "application/trust-mark+jwt", issuedMarkClaims())
		}},
		{name: "a trust mark with optional claims", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("exp", time.Now().Add(time.Hour).Unix()))
		}},
		{name: "a value that is not a JWT", cause: "not a compact JWS", mark: func(*testing.T) string { return "<html>" + marker + "</html>" }},
		{name: "two segments", cause: "not a compact JWS", mark: func(t *testing.T) string {
			return encodedSegment(t, header) + "." + encodedSegment(t, issuedMarkClaims())
		}},
		{name: "four segments", cause: "not a compact JWS", mark: func(t *testing.T) string {
			return encodedSegment(t, header) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature + "." + signature
		}},
		{name: "a header that is not base64url", cause: "header is not base64url", mark: func(t *testing.T) string {
			return "!!." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header that is not a JSON object", cause: "header is not a JSON object", mark: func(t *testing.T) string {
			return encodedSegment(t, []string{marker}) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header with no typ", cause: "'typ' header", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("typ", nil)) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header typed as an entity statement", cause: "'typ' header", mark: func(t *testing.T) string {
			return signedTrustMark(t, "entity-statement+jwt", issuedMarkClaims())
		}},
		{name: "a header with a typ that is not a string", cause: "'typ' header", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("typ", 7)) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header with alg none", cause: "not signed", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("alg", "none")) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header with no alg", cause: "not signed", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("alg", nil)) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header with no kid", cause: "'kid' header", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("kid", nil)) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header with an empty kid", cause: "'kid' header", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("kid", "")) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "a header with a kid that is not a string", cause: "'kid' header", mark: func(t *testing.T) string {
			return encodedSegment(t, headerWith("kid", 7)) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature
		}},
		{name: "an empty signature", cause: "no signature", mark: func(t *testing.T) string {
			return encodedSegment(t, header) + "." + encodedSegment(t, issuedMarkClaims()) + "."
		}},
		{name: "a signature that is not base64url", cause: "no signature", mark: func(t *testing.T) string {
			return encodedSegment(t, header) + "." + encodedSegment(t, issuedMarkClaims()) + "." + signature + "!!"
		}},
		{name: "a payload that is not base64url", cause: "payload is not base64url", mark: func(t *testing.T) string {
			return encodedSegment(t, header) + ".!!." + signature
		}},
		{name: "a payload with no iat", cause: "payload is not a trust mark", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("iat", nil))
		}},
		{name: "a payload with no trust_mark_type", cause: "payload is not a trust mark", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("trust_mark_type", nil))
		}},
		{name: "a trust mark another entity issued", cause: "'iss' is not this server", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("iss", "https://other-issuer.example.com"))
		}},
		{name: "a trust mark for another subject", cause: "'sub' is not the requested subject", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("sub", "https://other.example.com"))
		}},
		{name: "a trust mark for the subject spelled differently", cause: "'sub' is not the requested subject", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("sub", "https://SUB.example.com"))
		}},
		{name: "a trust mark of another type", cause: "'trust_mark_type' is not the requested type", mark: func(t *testing.T) string {
			return signedTrustMark(t, "trust-mark+jwt", with("trust_mark_type", "https://tm.example.com/other"))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mark := tc.mark(t)
			var logs bytes.Buffer
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:    issuedMarkIssuer,
				SignerConfiguration: model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
				TrustMarkRetriever:  fixedTrustMarkRetriever{issued: mark},
				Configuration:       model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			defer ts.Close()

			response, err := ts.Client().Get(ts.URL + "/trust-mark?sub=" + issuedMarkSubject + "&trust_mark_type=" + issuedMarkType)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if tc.cause == "" {
				if response.StatusCode != http.StatusOK || string(raw) != mark {
					t.Fatalf("[8.6.2] expected the trust mark served at 200, got %d %s", response.StatusCode, raw)
				}
				if ct := response.Header.Get("Content-Type"); ct != "application/trust-mark+jwt" {
					t.Errorf("[8.6.2] expected application/trust-mark+jwt, got %q", ct)
				}
				return
			}
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("[8.6.2] expected a value that is not the requested trust mark refused with 500, got %d %s", response.StatusCode, raw)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if answer["error"] != model.ServerError || answer["error_description"] != trustMarkUnavailableError {
				t.Errorf("[8.9] expected server_error with the endpoint's fixed description, got %s", raw)
			}
			if strings.Contains(string(raw), marker) || strings.Contains(string(raw), tc.cause) {
				t.Errorf("expected nothing about the retriever's value in the response, got %s", raw)
			}
			errorLines := 0
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) {
					errorLines++
					if !strings.Contains(line, tc.cause) {
						t.Errorf("expected the Error line to name the cause %q, got %s", tc.cause, line)
					}
					if strings.Contains(line, marker) {
						t.Errorf("expected the retriever's value not logged, got %s", line)
					}
				}
			}
			if errorLines != 1 {
				t.Errorf("expected one Error line, because the retriever is this deployment's own, got %d: %s", errorLines, logs.String())
			}
		})
	}
}
