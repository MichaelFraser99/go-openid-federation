package server

import (
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

func TestNewServer_ALeafsUnpublishedEndpointsAreLoggedOnceNotPerRequest(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	logs := &lockedBuffer{}
	server := NewServer(model.ServerConfiguration{
		Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
		EntityIdentifier:            "https://leaf.example.com",
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "leaf"},
		EntityConfigurationLifetime: time.Hour,
		EntityConfiguration: model.EntityStatement{Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{
			"federation_fetch_endpoint": "https://elsewhere.example.com/fetch",
			"federation_list_endpoint":  "https://elsewhere.example.com/list",
		}}},
	})
	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	for range 3 {
		response, err := ts.Client().Get(ts.URL + "/.well-known/openid-federation")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected the leaf's entity configuration, got %d", response.StatusCode)
		}
	}

	for _, claim := range []string{"federation_fetch_endpoint", "federation_list_endpoint"} {
		lines := 0
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, claim) {
				lines++
			}
		}
		if lines != 1 {
			t.Errorf("[5.1.1] expected the unpublished %s logged at error level once, when the server is built, not on every request, got %d lines: %s", claim, lines, logs.String())
		}
	}
}
