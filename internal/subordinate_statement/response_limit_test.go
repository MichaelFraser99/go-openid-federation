package subordinate_statement

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_BoundsPeerResponseBodySize(t *testing.T) {
	tests := []struct {
		name      string
		limit     int64
		bodyBytes int
		expectErr bool
	}{
		{name: "a response within the limit is read", limit: 4096, bodyBytes: 512, expectErr: false},
		{name: "a response exactly at the limit is read", limit: 4096, bodyBytes: 4096, expectErr: false},
		{name: "a response over the limit is refused", limit: 4096, bodyBytes: 1 << 20, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var served atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				remaining := tc.bodyBytes
				for remaining > 0 {
					chunk := 1024
					if remaining < chunk {
						chunk = remaining
					}
					n, err := w.Write([]byte(strings.Repeat("a", chunk)))
					served.Add(int64(n))
					remaining -= chunk
					if err != nil {
						return
					}
				}
			}))
			t.Cleanup(server.Close)

			cfg := model.Configuration{HttpClient: server.Client(), MaxPeerResponseBytes: tc.limit}
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
			if tc.expectErr {
				if !strings.Contains(err.Error(), "response limit") {
					t.Fatalf("expected the response limit to be reported, got %v", err)
				}
				if streamed := served.Load(); streamed >= int64(tc.bodyBytes) {
					t.Errorf("expected the read to stop early, the peer streamed the whole %d byte body", streamed)
				}
				return
			}
			if strings.Contains(err.Error(), "response limit") {
				t.Fatalf("expected a response within the limit to be read, got %v", err)
			}
		})
	}
}
