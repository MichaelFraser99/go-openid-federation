package subordinate_statement

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func stallingFetchEndpoint(t *testing.T, writeHeaders bool) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if writeHeaders {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server
}

func issuerWithFetchEndpoint(t *testing.T, endpoint string) model.EntityStatement {
	t.Helper()
	key := testKey(t)
	return model.EntityStatement{
		Iss:      "https://ta.example.com",
		Sub:      "https://ta.example.com",
		Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": endpoint}},
		JWKs:     josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, key.Public(), "ta")}},
	}
}

func retrieveWithin(t *testing.T, ctx context.Context, cfg model.Configuration, issuer model.EntityStatement) (time.Duration, error) {
	t.Helper()
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		_, _, err := Retrieve(ctx, cfg, issuer, "https://leaf.example.com")
		done <- err
	}()

	select {
	case err := <-done:
		return time.Since(started), err
	case <-time.After(30 * time.Second):
		t.Fatal("[8.2] the fetch never returned, so a peer that stays silent holds this request open")
		return 0, nil
	}
}

func TestRetrieve_AStalledFetchEndpointIsBoundedAndStaysAPeerFault(t *testing.T) {
	tests := map[string]struct {
		reference    string
		writeHeaders bool
	}{
		"an endpoint that never responds":           {reference: "8.9", writeHeaders: false},
		"an endpoint that sends headers and stalls": {reference: "8.9", writeHeaders: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := stallingFetchEndpoint(t, tc.writeHeaders)
			cfg := model.Configuration{HttpClient: server.Client(), MaxPeerResponseTime: 100 * time.Millisecond}

			elapsed, err := retrieveWithin(t, t.Context(), cfg, issuerWithFetchEndpoint(t, server.URL+"/fetch"))
			if elapsed >= 5*time.Second {
				t.Fatalf("[%s] a 100ms peer deadline must bound this fetch, took %v, so the configured value is not the one applied", tc.reference, elapsed)
			}
			if err == nil {
				t.Fatalf("[%s] a peer that outlives its deadline must not produce a statement", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[%s] a peer that outlives its deadline is the peer's fault, so invalid_trust_chain, got %v", tc.reference, err)
			}
			if errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Errorf("[%s] temporarily_unavailable is this server's own deadline, not a peer's, got %v", tc.reference, err)
			}
		})
	}
}

func TestRetrieve_ThePeerDeadlineDoesNotOutliveTheCallersOwn(t *testing.T) {
	server := stallingFetchEndpoint(t, false)
	cfg := model.Configuration{HttpClient: server.Client(), MaxPeerResponseTime: time.Hour}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	elapsed, err := retrieveWithin(t, ctx, cfg, issuerWithFetchEndpoint(t, server.URL+"/fetch"))
	if elapsed >= 5*time.Second {
		t.Fatalf("[8.9] a per-peer deadline of an hour must not outlive the caller's 100ms, took %v", elapsed)
	}
	if err == nil {
		t.Fatal("[8.9] a cancelled caller must not get a statement")
	}
	if !errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Errorf("[8.9] the caller's own deadline is this server not completing the request, so temporarily_unavailable, got %v", err)
	}
}
