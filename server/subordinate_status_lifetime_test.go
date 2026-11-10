package server

import (
	"encoding/base64"
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
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_SubordinateStatus_AResponseLifetimeUnderOneSecondIsAConfigurationFault(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	tests := []struct {
		name     string
		lifetime *time.Duration
		refused  bool
		validFor int64
	}{
		{name: "no lifetime, so the response carries no exp", lifetime: nil},
		{name: "one second", lifetime: model.Pointer(time.Second), validFor: 1},
		{name: "one hour", lifetime: model.Pointer(time.Hour), validFor: 3600},
		{name: "just under one second", lifetime: model.Pointer(999 * time.Millisecond), refused: true},
		{name: "zero", lifetime: model.Pointer(time.Duration(0)), refused: true},
		{name: "negative", lifetime: model.Pointer(-time.Hour), refused: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			s := NewServer(model.ServerConfiguration{
				Configuration:             model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				EntityIdentifier:          "https://ta.example.com",
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				IntermediateConfiguration: &model.IntermediateConfiguration{},
				Extensions: model.Extensions{SubordinateStatus: model.SubordinateStatusConfiguration{
					Enabled:           true,
					ResponseLifetime:  tc.lifetime,
					MetadataRetriever: TestSubordinateStatusRetriever{},
				}},
			})
			mux := http.NewServeMux()
			s.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/subordinate-status?sub=" + url.QueryEscape("https://federation.com/one-event"))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if tc.refused {
				var answer map[string]string
				if err := json.Unmarshal(raw, &answer); err != nil {
					t.Fatalf("failed to read the error %s: %v", raw, err)
				}
				if response.StatusCode != http.StatusInternalServerError || answer["error"] != model.ServerError || answer["error_description"] != subordinateStatusUnavailableError {
					t.Errorf("[8.9 server_error] a lifetime under one second can only sign a response already expired, so expected 500 server_error %q, got %d %s", subordinateStatusUnavailableError, response.StatusCode, raw)
				}
				logged := false
				for _, line := range strings.Split(logs.String(), "\n") {
					if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, "response lifetime must be at least one second") {
						logged = true
					}
				}
				if !logged {
					t.Errorf("expected the lifetime named at error level, got %s", logs.String())
				}
				return
			}

			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d %s", response.StatusCode, raw)
			}
			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(string(raw), ".")[1])
			if err != nil {
				t.Fatalf("failed to decode the payload: %v", err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("failed to read the payload: %v", err)
			}
			iat, _ := claims["iat"].(float64)
			exp, present := claims["exp"].(float64)
			if tc.lifetime == nil {
				if _, carried := claims["exp"]; carried {
					t.Errorf("[subordinate events 2.3.2] exp is OPTIONAL and no lifetime is configured, so expected none, got %v", claims["exp"])
				}
				return
			}
			if !present || int64(exp)-int64(iat) != tc.validFor {
				t.Errorf("expected exp to be iat plus %d seconds, got iat=%v exp=%v", tc.validFor, claims["iat"], claims["exp"])
			}
		})
	}
}
