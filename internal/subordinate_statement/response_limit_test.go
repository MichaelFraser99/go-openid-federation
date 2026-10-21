package subordinate_statement

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_BoundsPeerResponseBodySize(t *testing.T) {
	const limit int64 = 4096

	tests := []struct {
		name      string
		bodyBytes int64
		expectErr bool
	}{
		{name: "well under the limit is read", bodyBytes: 512, expectErr: false},
		{name: "one byte under the limit is read", bodyBytes: limit - 1, expectErr: false},
		{name: "exactly at the limit is read", bodyBytes: limit, expectErr: false},
		{name: "one byte over the limit is refused", bodyBytes: limit + 1, expectErr: true},
		{name: "far over the limit is refused", bodyBytes: 1 << 20, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				remaining := tc.bodyBytes
				for remaining > 0 {
					chunk := int64(1024)
					if remaining < chunk {
						chunk = remaining
					}
					if _, err := w.Write([]byte(strings.Repeat("a", int(chunk)))); err != nil {
						return
					}
					remaining -= chunk
				}
			}))
			t.Cleanup(server.Close)

			cfg := model.Configuration{HttpClient: server.Client(), MaxPeerResponseBytes: limit}
			issuer := model.EntityStatement{
				Iss: model.EntityIdentifier(server.URL),
				Sub: model.EntityIdentifier(server.URL),
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{
					"federation_fetch_endpoint": fmt.Sprintf("%s/fetch", server.URL),
				}},
				JWKs: josemodel.Jwks{},
			}

			_, _, err := Retrieve(context.Background(), cfg, issuer, "https://leaf.example.com")
			if err == nil {
				t.Fatal("expected an error, since the served body is not a valid subordinate statement")
			}

			reportsLimit := strings.Contains(err.Error(), "response limit")
			if tc.expectErr && !reportsLimit {
				t.Fatalf("expected the response limit to be reported for a %d byte body, got %v", tc.bodyBytes, err)
			}
			if !tc.expectErr && reportsLimit {
				t.Fatalf("expected a %d byte body within the %d byte limit to be read, got %v", tc.bodyBytes, limit, err)
			}
		})
	}
}

func TestRetrieve_AppliesTheDefaultResponseLimitWhenNoneIsConfigured(t *testing.T) {
	tests := map[string]struct {
		bodyBytes   int64
		expectLimit bool
	}{
		"well under the default limit is read":       {bodyBytes: 4096, expectLimit: false},
		"one byte over the default limit is refused": {bodyBytes: model.DefaultMaxPeerResponseBytes + 1, expectLimit: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				remaining := tc.bodyBytes
				for remaining > 0 {
					chunk := int64(4096)
					if remaining < chunk {
						chunk = remaining
					}
					if _, err := w.Write([]byte(strings.Repeat("a", int(chunk)))); err != nil {
						return
					}
					remaining -= chunk
				}
			}))
			t.Cleanup(server.Close)

			cfg := model.Configuration{HttpClient: server.Client()}
			issuer := model.EntityStatement{
				Iss: model.EntityIdentifier(server.URL),
				Sub: model.EntityIdentifier(server.URL),
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{
					"federation_fetch_endpoint": fmt.Sprintf("%s/fetch", server.URL),
				}},
				JWKs: josemodel.Jwks{},
			}

			_, _, err := Retrieve(context.Background(), cfg, issuer, "https://leaf.example.com")
			if err == nil {
				t.Fatal("expected an error, since the served body is not a valid subordinate statement")
			}
			reportsLimit := strings.Contains(err.Error(), "response limit")
			if tc.expectLimit && !reportsLimit {
				t.Fatalf("expected the default %d byte limit to refuse a %d byte body, got %v", model.DefaultMaxPeerResponseBytes, tc.bodyBytes, err)
			}
			if !tc.expectLimit && reportsLimit {
				t.Fatalf("expected a %d byte body within the default %d byte limit to be read, got %v", tc.bodyBytes, model.DefaultMaxPeerResponseBytes, err)
			}
		})
	}
}

func TestRetrieve_StopsReadingAtTheLimitRatherThanBuffering(t *testing.T) {
	const limit int64 = 4096

	released := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		if _, err := w.Write([]byte(strings.Repeat("a", int(limit+1)))); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-released:
		case <-time.After(30 * time.Second):
		}
	}))
	t.Cleanup(func() {
		close(released)
		server.Close()
	})

	cfg := model.Configuration{HttpClient: server.Client(), MaxPeerResponseBytes: limit}
	issuer := model.EntityStatement{
		Iss: model.EntityIdentifier(server.URL),
		Sub: model.EntityIdentifier(server.URL),
		Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{
			"federation_fetch_endpoint": fmt.Sprintf("%s/fetch", server.URL),
		}},
		JWKs: josemodel.Jwks{},
	}

	returned := make(chan error, 1)
	go func() {
		_, _, err := Retrieve(context.Background(), cfg, issuer, "https://leaf.example.com")
		returned <- err
	}()

	select {
	case err := <-returned:
		if err == nil || !strings.Contains(err.Error(), "response limit") {
			t.Fatalf("expected the response limit to be reported, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Retrieve did not return while the peer was still holding the response open, so the read is not bounded by the limit")
	}
}
