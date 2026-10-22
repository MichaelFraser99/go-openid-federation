package subordinate_statement

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_WhatAPeerChoosesIsBoundedInTheLog(t *testing.T) {
	const marker = "LOG-TAIL-MARKER"
	padding := strings.Repeat("a", 8192)

	tests := []struct {
		name      string
		reference string
		handler   func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name:      "a content type of the peer's choosing",
			reference: "8.9",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain; p="+padding+marker)
				_, _ = w.Write([]byte("body"))
			},
		},
		{
			name:      "a status line of the peer's choosing",
			reference: "8.9",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close() //nolint:errcheck
				_, _ = conn.Write([]byte("HTTP/1.1 418 " + padding + marker + "\r\nContent-Length: 0\r\n\r\n"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(tc.handler))
			t.Cleanup(server.Close)

			key := testKey(t)
			issuerJwk := testPublicJwk(t, key.Public(), "ta")
			id := model.EntityIdentifier(server.URL)
			issuer := model.EntityStatement{
				Iss:      id,
				Sub:      id,
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": server.URL + "/fetch"}},
				JWKs:     josemodel.Jwks{Keys: []map[string]any{issuerJwk}},
			}

			var logs bytes.Buffer
			cfg := model.Configuration{
				HttpClient: server.Client(),
				Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}

			if _, _, err := Retrieve(t.Context(), cfg, issuer, "https://leaf.example.com"); err == nil {
				t.Fatalf("[%s] expected the response to be refused", tc.reference)
			}
			if strings.Contains(logs.String(), marker) {
				t.Errorf("[%s] the log carries the whole value the peer chose (%d bytes logged)", tc.reference, logs.Len())
			}
			if strings.Contains(logs.String(), padding) {
				t.Errorf("[%s] the log carries %d bytes of the peer's padding", tc.reference, len(padding))
			}
		})
	}
}
