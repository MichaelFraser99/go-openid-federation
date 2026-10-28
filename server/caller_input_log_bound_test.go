package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServer_WhatACallerSendsIsBoundedInTheLog(t *testing.T) {
	const marker = "CALLER-TAIL-MARKER-ZZZZ"
	padding := strings.Repeat("p", 8192)
	shapes := map[string]string{
		"a well-formed identifier": "https://caller.invalid/" + padding + marker,
		"a malformed identifier":   "http://caller.invalid/" + padding + marker,
		"an opaque value":          padding + marker,
	}

	requests := map[string]func(value string) *http.Request{
		"fetch": func(v string) *http.Request {
			return httpGet("/fetch?" + url.Values{"sub": {v}}.Encode())
		},
		"resolve": func(v string) *http.Request {
			return httpGet("/resolve?" + url.Values{"sub": {v}, "trust_anchor": {v}, "entity_type": {v}}.Encode())
		},
		"list": func(v string) *http.Request {
			return httpGet("/list?" + url.Values{"entity_type": {v}, "trust_mark_type": {v}, "intermediate": {v}, "trust_marked": {v}}.Encode())
		},
		"extended-list": func(v string) *http.Request {
			return httpGet("/extended-list?" + url.Values{"from": {v}, "entity_type": {v}, "trust_mark_type": {v}, "limit": {v}, "claims": {v}}.Encode())
		},
		"subordinate-status": func(v string) *http.Request {
			return httpGet("/subordinate-status?" + url.Values{"sub": {v}}.Encode())
		},
		"trust-mark": func(v string) *http.Request {
			return httpGet("/trust-mark?" + url.Values{"trust_mark_type": {v}, "sub": {v}}.Encode())
		},
		"trust-mark-list": func(v string) *http.Request {
			return httpGet("/trust-mark-list?" + url.Values{"trust_mark_type": {v}, "sub": {v}}.Encode())
		},
		"trust-mark-status": func(v string) *http.Request {
			request, _ := http.NewRequest(http.MethodPost, "/trust-mark-status", strings.NewReader(url.Values{"trust_mark": {v}}.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return request
		},
	}

	for endpoint, build := range requests {
		for shape, value := range shapes {
			t.Run(endpoint+" with "+shape, func(t *testing.T) {
				var logs lockedBuffer
				ts := contractServer(t, func(cfg *model.ServerConfiguration) {
					cfg.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
					cfg.TrustAnchors = map[model.EntityIdentifier]josemodel.Jwks{}
					cfg.TrustMarkRetriever = nilListingTrustMarkRetriever{}
					cfg.Extensions = model.Extensions{
						ExtendedListing:   model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: cursorRetriever{}},
						SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: emptyStatusRetriever{}},
					}
				})

				request := build(value)
				target, err := url.Parse(ts.URL + request.URL.String())
				if err != nil {
					t.Fatal(err)
				}
				request.URL = target
				request.Host = target.Host
				response, err := ts.Client().Do(request)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()

				for _, line := range strings.Split(logs.String(), "\n") {
					if strings.Contains(line, marker) {
						var entry map[string]any
						_ = json.Unmarshal([]byte(line), &entry)
						keys := []string{}
						for k, v := range entry {
							if s, ok := v.(string); ok && strings.Contains(s, marker) {
								keys = append(keys, k)
							}
						}
						t.Logf("LEAK msg=%q keys=%v", entry["msg"], keys)
					}
				}
				if strings.Contains(logs.String(), marker) {
					t.Errorf("the tail of a %d byte caller value reached the log, so what a caller sends is not bounded there", len(value))
				}
				if strings.Contains(string(body), marker) {
					t.Errorf("the tail of a %d byte caller value reached the response body", len(value))
				}
			})
		}
	}
}

func httpGet(target string) *http.Request {
	request, _ := http.NewRequest(http.MethodGet, target, nil)
	return request
}
