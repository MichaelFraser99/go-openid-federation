package server

import (
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
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_AnEntityConfigurationThatSetsABuiltInTypeThroughExtensionsIsNotPublished(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	for _, intermediate := range []bool{false, true} {
		name := "a leaf"
		if intermediate {
			name = "an intermediate"
		}
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuffer{}
			cfg := model.ServerConfiguration{
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				EntityIdentifier:            "https://entity.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "own"},
				EntityConfigurationLifetime: time.Hour,
				EntityConfiguration: model.EntityStatement{Metadata: &model.Metadata{
					Extensions: map[string]map[string]any{"federation_entity": {"federation_fetch_endpoint": "https://elsewhere.example.com/fetch"}},
				}},
			}
			if intermediate {
				cfg.IntermediateConfiguration = &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour}
			}
			mux := http.NewServeMux()
			NewServer(cfg).Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/.well-known/openid-federation")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil || response.StatusCode != http.StatusInternalServerError || answer["error"] != model.ServerError || answer["error_description"] != entityConfigurationUnavailableError {
				t.Errorf("[5.1.1] an Extensions entry would replace the endpoints this server must publish, so expected 500 server_error %q, got %d %s", entityConfigurationUnavailableError, response.StatusCode, raw)
			}
			logged := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, "Metadata.FederationMetadata") {
					logged = true
				}
			}
			if !logged {
				t.Errorf("expected the cause named at error level, got %s", logs.String())
			}
		})
	}
}
