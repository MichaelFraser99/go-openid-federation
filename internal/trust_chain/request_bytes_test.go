package trust_chain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func paddedHintGraph(t *testing.T, hints map[string][]string, padding int, fetches *atomic.Int64) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		hs, ok := hints[node]
		if !ok || !strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			http.NotFound(w, r)
			return
		}
		fetches.Add(1)
		ids := make([]model.EntityIdentifier, 0, len(hs))
		for _, h := range hs {
			ids = append(ids, model.EntityIdentifier(srv.URL+"/"+h))
		}
		self := model.EntityIdentifier(srv.URL + "/" + node)
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(createPaddedEntityStatement(t, self, self, ids, key, padding)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildTrustChain_BoundsTheBytesOneRequestHolds(t *testing.T) {
	hints := sharedDeadEndGraph(40, false)
	for i := range 40 {
		hints[fmt.Sprintf("leaf%d", i)] = []string{fmt.Sprintf("d%d", i)}
	}

	const padding = 20_000
	var fetches atomic.Int64
	srv := paddedHintGraph(t, hints, padding, &fetches)

	cfg := model.Configuration{
		HttpClient:          srv.Client(),
		MaxRequestPeerBytes: 100_000,
	}
	cache := resolvecache.New()

	anchor := model.EntityIdentifier(srv.URL + "/ta")
	var limitReached bool
	for i := range 40 {
		_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(fmt.Sprintf("%s/leaf%d", srv.URL, i)), anchor, cache)
		if err == nil {
			t.Fatal("this graph reaches no trust anchor, so the walk must fail")
		}
		if errors.Is(err, model.ErrLimitReached) {
			limitReached = true
		}
	}

	if !limitReached {
		t.Fatalf("[8.2] a request holding more than %d bytes of peer statements must be refused as a limit, having held %d", cfg.RequestPeerBytesLimit(), cache.PeerBytes())
	}
	if got := cache.PeerBytes(); got > cfg.RequestPeerBytesLimit()+int64(cfg.PeerResponseLimit()) {
		t.Errorf("the bytes held may overshoot the budget by at most one response, held %d against a budget of %d and a per-response cap of %d", got, cfg.RequestPeerBytesLimit(), cfg.PeerResponseLimit())
	}
}

func TestBuildTrustChain_AByteBudgetRefusalIsALimitNotAServerFault(t *testing.T) {
	hints := sharedDeadEndGraph(10, false)
	for i := range 10 {
		hints[fmt.Sprintf("leaf%d", i)] = []string{fmt.Sprintf("d%d", i)}
	}

	var fetches atomic.Int64
	srv := paddedHintGraph(t, hints, 20_000, &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxRequestPeerBytes: 1}
	cache := resolvecache.New()

	_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf0"), model.EntityIdentifier(srv.URL+"/ta"), cache)
	if err == nil {
		t.Fatal("expected the walk to fail")
	}
	if !errors.Is(err, model.ErrLimitReached) {
		t.Errorf("a budget the caller's own graph exhausted is a limit, got %v", err)
	}
	if errors.Is(err, model.ErrServerError) || errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Errorf("the graph is the caller's choice, so exhausting a bound is neither this server's fault nor temporary, got %v", err)
	}
}

func TestConfiguration_TheByteBudgetIsOnByDefault(t *testing.T) {
	var cfg model.Configuration
	if cfg.RequestPeerBytesLimit() != model.DefaultMaxRequestPeerBytes {
		t.Errorf("expected the bytes one request may hold to be bounded by default, got %d", cfg.RequestPeerBytesLimit())
	}

	tests := map[string]int64{"zero applies the default": 0, "negative applies the default": -1}
	for name, configured := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.Configuration{MaxRequestPeerBytes: configured}
			if cfg.RequestPeerBytesLimit() != model.DefaultMaxRequestPeerBytes {
				t.Errorf("expected the default, got %d", cfg.RequestPeerBytesLimit())
			}
		})
	}
}

func TestCache_PeerBytesCountsWhatItHolds(t *testing.T) {
	cache := resolvecache.New()
	if got := cache.PeerBytes(); got != 0 {
		t.Errorf("a new cache holds nothing, got %d", got)
	}

	if got := cache.RecordPeerBytes(100); got != 100 {
		t.Errorf("expected 100, got %d", got)
	}
	if got := cache.RecordPeerBytes(250); got != 350 {
		t.Errorf("expected the running total 350, got %d", got)
	}
	if got := cache.PeerBytes(); got != 350 {
		t.Errorf("expected 350, got %d", got)
	}

	var absent *resolvecache.Cache
	if got := absent.RecordPeerBytes(100); got != 0 {
		t.Errorf("a nil cache charges nothing, got %d", got)
	}
	if got := absent.PeerBytes(); got != 0 {
		t.Errorf("a nil cache holds nothing, got %d", got)
	}
}

func createPaddedEntityStatement(t *testing.T, iss, sub model.EntityIdentifier, authorityHints []model.EntityIdentifier, signer crypto.Signer, padding int) string {
	t.Helper()

	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to create public JWK: %v", err)
	}
	(*publicJWK)["kid"] = "test-key"

	body := map[string]any{
		"iss":  string(iss),
		"sub":  string(sub),
		"iat":  time.Now().UTC().Unix(),
		"exp":  time.Now().Add(24 * time.Hour).UTC().Unix(),
		"jwks": map[string]any{"keys": []any{*publicJWK}},
		"ref":  strings.Repeat("p", padding),
	}

	if len(authorityHints) > 0 {
		hints := make([]string, len(authorityHints))
		for i, hint := range authorityHints {
			hints[i] = string(hint)
		}
		body["authority_hints"] = hints
	}

	body["metadata"] = map[string]any{
		"federation_entity": map[string]any{"federation_fetch_endpoint": fmt.Sprintf("%s/fetch", iss)},
	}

	token, err := jwt.New(signer, map[string]any{"kid": "test-key", "typ": "entity-statement+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to create entity statement: %v", err)
	}
	return *token
}
