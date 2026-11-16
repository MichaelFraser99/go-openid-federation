package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func servedLeaf(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	server := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
		EntityConfigurationLifetime: time.Hour,
	})
	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return server, ts
}

func publishedIssuer(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	response, err := client.Get(url + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("expected the entity configuration, got %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", response.StatusCode, body)
	}
	parts := strings.Split(string(body), ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %s", body)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the payload: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to parse the payload: %v", err)
	}
	return claims.Iss
}

func TestServer_SettersTakeEffectOnTheNextRequest(t *testing.T) {
	server, ts := servedLeaf(t)

	server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
	if got := publishedIssuer(t, ts.Client(), ts.URL); got != ts.URL {
		t.Errorf("expected the entity configuration to be issued by %s, got %s", ts.URL, got)
	}

	renamed := ts.URL + "/renamed"
	server.SetEntityIdentifier(model.EntityIdentifier(renamed))
	if got := publishedIssuer(t, ts.Client(), ts.URL); got != renamed {
		t.Errorf("expected the entity configuration to be issued by %s, got %s", renamed, got)
	}

	client := ts.Client()
	server.SetHttpClient(client)
	if server.config().HttpClient != client {
		t.Errorf("expected the HTTP client to be the one set")
	}
	if server.config().EntityIdentifier != model.EntityIdentifier(renamed) {
		t.Errorf("expected setting the HTTP client to keep the entity identifier, got %s", server.config().EntityIdentifier)
	}
}

func TestServer_SettersDoNotRaceWithServing(t *testing.T) {
	server, ts := servedLeaf(t)
	server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
	client := ts.Client()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
				server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
				server.SetHttpClient(client)
			}
		}
	})
	for range 20 {
		if got := publishedIssuer(t, client, ts.URL); got != ts.URL {
			t.Errorf("expected the entity configuration to be issued by %s, got %s", ts.URL, got)
		}
	}
	close(done)
	wg.Wait()
}

func TestServer_ConcurrentSettersKeepBothChanges(t *testing.T) {
	const identifier = model.EntityIdentifier("https://entity.example.com")
	client := &http.Client{}

	for trial := range 2000 {
		server := NewServer(model.ServerConfiguration{})
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			server.SetEntityIdentifier(identifier)
		})
		wg.Go(func() {
			<-start
			server.SetHttpClient(client)
		})
		close(start)
		wg.Wait()

		if server.config().EntityIdentifier != identifier || server.config().HttpClient != client {
			t.Fatalf("trial %d: a concurrent setter lost the other's change, got identifier %q and client %p", trial, server.config().EntityIdentifier, server.config().HttpClient)
		}
	}
}

func TestServer_AZeroValueServerReadsAnEmptyConfiguration(t *testing.T) {
	var server Server
	if cfg := server.config(); cfg == nil || cfg.EntityIdentifier != "" {
		t.Fatalf("expected an empty configuration, got %+v", cfg)
	}
	server.SetEntityIdentifier("https://entity.example.com")
	if got := server.config().EntityIdentifier; got != "https://entity.example.com" {
		t.Errorf("expected a setter on a zero-value server to take effect, got %s", got)
	}
}
