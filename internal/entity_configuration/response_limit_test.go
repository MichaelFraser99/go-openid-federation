package entity_configuration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_BoundsPeerResponseBodySize(t *testing.T) {
	tests := []struct {
		name      string
		limit     int64
		bodyBytes int
		expectErr bool
	}{
		{
			name:      "a response within the limit is read",
			limit:     4096,
			bodyBytes: 512,
			expectErr: false,
		},
		{
			name:      "a response over the limit is refused",
			limit:     4096,
			bodyBytes: 1 << 20,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var served atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				chunk := strings.Repeat("a", 1024)
				for written := 0; written < tc.bodyBytes; written += len(chunk) {
					n, err := w.Write([]byte(chunk))
					served.Add(int64(n))
					if err != nil {
						return
					}
				}
			}))
			t.Cleanup(server.Close)

			cfg := model.Configuration{
				HttpClient:           server.Client(),
				MaxPeerResponseBytes: tc.limit,
			}

			_, _, err := Retrieve(context.Background(), cfg, model.EntityIdentifier(server.URL), resolvecache.New())
			if err == nil {
				t.Fatal("expected an error, since the served body is not a valid entity configuration")
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
