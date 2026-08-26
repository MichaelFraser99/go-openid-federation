package entity_configuration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/server_test"
)

type countingRoundTripper struct {
	next  http.RoundTripper
	count int
}

func (c *countingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	c.count++
	return c.next.RoundTrip(r)
}

type failOnceRoundTripper struct {
	next   http.RoundTripper
	failed bool
}

func (f *failOnceRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if !f.failed {
		f.failed = true
		return nil, fmt.Errorf("transient network error")
	}
	return f.next.RoundTrip(r)
}

func TestRetrieve_DoesNotCacheErrors(t *testing.T) {
	testServer := server_test.TestServer(t)
	identifier := model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServer.URL))

	transport := &failOnceRoundTripper{next: testServer.Client().Transport}
	cfg := model.Configuration{HttpClient: &http.Client{Transport: transport}}
	cache := resolvecache.New()

	if _, _, err := Retrieve(t.Context(), cfg, identifier, cache); err == nil {
		t.Fatal("expected the first retrieval to fail transiently")
	}

	signed, statement, err := Retrieve(t.Context(), cfg, identifier, cache)
	if err != nil {
		t.Fatalf("expected the retry to succeed (a transient error must not be cached), got %q", err.Error())
	}
	if signed == nil || statement == nil {
		t.Fatal("expected a successful statement on retry")
	}
}

func TestRetrieve_CachesByIdentifier(t *testing.T) {
	testServer := server_test.TestServer(t)
	identifier := model.EntityIdentifier(fmt.Sprintf("%s/leaf", testServer.URL))

	tests := map[string]struct {
		useCache    bool
		wantFetches int
	}{
		"repeated retrieval with a cache fetches once": {
			useCache:    true,
			wantFetches: 1,
		},
		"repeated retrieval without a cache fetches every time": {
			useCache:    false,
			wantFetches: 2,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			counter := &countingRoundTripper{next: testServer.Client().Transport}
			cfg := model.Configuration{HttpClient: &http.Client{Transport: counter}}

			var cache *resolvecache.Cache
			if tt.useCache {
				cache = resolvecache.New()
			}

			for i := range 2 {
				signed, statement, err := Retrieve(t.Context(), cfg, identifier, cache)
				if err != nil {
					t.Fatalf("call %d: expected no error, got %q", i, err.Error())
				}
				if signed == nil || statement == nil {
					t.Fatalf("call %d: expected non-nil signed statement and result", i)
				}
			}

			if counter.count != tt.wantFetches {
				t.Fatalf("outbound fetches = %d, want %d", counter.count, tt.wantFetches)
			}
		})
	}
}
