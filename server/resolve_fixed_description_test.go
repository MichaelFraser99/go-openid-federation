package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_ThisServersOwnFaultAnswersTheFixedDescription(t *testing.T) {
	const (
		subject = "https://leaf.example.com"
		anchor  = "https://ta.example.com"
	)
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	tests := []struct {
		name        string
		reference   string
		configure   func(cfg *model.Configuration)
		status      int
		code        string
		description string
		cause       string
	}{
		{
			name:        "with no http client",
			reference:   "8.9 server_error",
			configure:   func(*model.Configuration) {},
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: resolveUnavailableError,
			cause:       "no http client present",
		},
		{
			name:      "with signing algorithms set but empty",
			reference: "8.9 server_error",
			configure: func(cfg *model.Configuration) {
				cfg.SigningAlgorithms = []jwa.Algorithm{}
			},
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: resolveUnavailableError,
			cause:       "SigningAlgorithms is set but empty",
		},
		{
			name:      "with no usable key held for the requested trust anchor",
			reference: "8.9 server_error",
			configure: func(cfg *model.Configuration) {
				cfg.TrustAnchors = map[model.EntityIdentifier]josemodel.Jwks{anchor: {Keys: []map[string]any{{"kty": "oct", "k": "c2VjcmV0", "kid": "ta"}}}}
			},
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: resolveUnavailableError,
			cause:       "hold no key that can verify a signature",
		},
		{
			name:      "with keys held only for another trust anchor",
			reference: "8.9 invalid_trust_anchor",
			configure: func(cfg *model.Configuration) {
				cfg.TrustAnchors = map[model.EntityIdentifier]josemodel.Jwks{"https://other-ta.example.com": {}}
			},
			status:      http.StatusNotFound,
			code:        model.InvalidTrustAnchor,
			description: "the requested trust anchor is not one this deployment is configured to trust",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			configuration := model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}
			tc.configure(&configuration)
			s := NewServer(model.ServerConfiguration{
				Configuration:               configuration,
				EntityIdentifier:            anchor,
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
			})
			mux := http.NewServeMux()
			s.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/resolve?sub=" + url.QueryEscape(subject) + "&trust_anchor=" + url.QueryEscape(anchor))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if response.StatusCode != tc.status || answer["error"] != tc.code || answer["error_description"] != tc.description {
				t.Errorf("[%s] expected %d %s %q, got %d %s", tc.reference, tc.status, tc.code, tc.description, response.StatusCode, raw)
			}

			if tc.cause == "" {
				return
			}
			logged := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, `"msg":"error building trust chain"`) && strings.Contains(line, tc.cause) {
					logged = true
				}
			}
			if !logged {
				t.Errorf("expected the cause %q logged at error level by the resolve endpoint, got %s", tc.cause, logs.String())
			}
		})
	}
}
