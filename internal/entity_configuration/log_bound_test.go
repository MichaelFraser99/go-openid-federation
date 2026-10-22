package entity_configuration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_WhatAPeerChoosesIsBoundedInTheRefusal(t *testing.T) {
	const marker = "EC-TAIL-MARKER"
	padding := strings.Repeat("a", 8192)

	tests := []struct {
		name      string
		reference string
		handler   func(w http.ResponseWriter, r *http.Request)
	}{
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
		{
			name:      "a content type of the peer's choosing",
			reference: "8.9",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain; p="+padding+marker)
				_, _ = w.Write([]byte("body"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(tc.handler))
			t.Cleanup(server.Close)

			cfg := model.Configuration{HttpClient: server.Client()}
			_, _, err := Retrieve(t.Context(), cfg, model.EntityIdentifier(server.URL), resolvecache.New())
			if err == nil {
				t.Fatalf("[%s] expected the response to be refused", tc.reference)
			}
			if strings.Contains(err.Error(), padding) {
				t.Errorf("[%s] the refusal carries %d bytes the peer chose, so it reaches a log and a response unbounded: %d byte error", tc.reference, len(padding), len(err.Error()))
			}
		})
	}
}
