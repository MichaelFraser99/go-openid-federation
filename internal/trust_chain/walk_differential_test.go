package trust_chain

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func reachableWithin(hints map[string][]string, from, target string, limit int, path []string) bool {
	if len(path)+1 > limit {
		return false
	}
	path = append(path, from)
	if from == target {
		return true
	}
	for _, hint := range hints[from] {
		if slices.Contains(path, hint) {
			continue
		}
		if reachableWithin(hints, hint, target, limit, path) {
			return true
		}
	}
	return false
}

type swappableGraph struct {
	mu    sync.Mutex
	hints map[string][]string
}

func (g *swappableGraph) set(hints map[string][]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hints = hints
}

func (g *swappableGraph) get(node string) ([]string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	hs, ok := g.hints[node]
	return hs, ok
}

func TestChainUpOne_MatchesReachabilityOnRandomGraphs(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	graph := &swappableGraph{hints: map[string][]string{}}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		hs, ok := graph.get(node)
		if !ok || !strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			http.NotFound(w, r)
			return
		}
		ids := make([]model.EntityIdentifier, 0, len(hs))
		for _, h := range hs {
			ids = append(ids, model.EntityIdentifier(srv.URL+"/"+h))
		}
		self := model.EntityIdentifier(srv.URL + "/" + node)
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(createEntityStatement(t, self, self, ids, key, true)))
	}))
	t.Cleanup(srv.Close)

	const limit = 4
	rng := rand.New(rand.NewPCG(1, 2))
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: limit, MaxEntitiesTraversed: 10000}
	leaf := model.EntityIdentifier(srv.URL + "/n0")
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	for iteration := range 400 {
		nodes := 3 + rng.IntN(5)
		names := make([]string, nodes)
		for i := range names {
			names[i] = fmt.Sprintf("n%d", i)
		}
		candidates := append(append([]string{}, names...), "ta")
		hints := map[string][]string{"ta": nil}
		for _, node := range names {
			var hs []string
			for _, other := range candidates {
				if rng.IntN(3) == 0 {
					hs = append(hs, other)
				}
			}
			hints[node] = hs
		}
		graph.set(hints)

		_, route, _, err := ChainUpOne(t.Context(), cfg, leaf, anchor, nil, nil, nil, resolvecache.New())
		found := err == nil && len(route) > 0
		want := reachableWithin(hints, "n0", "ta", limit, nil)
		if found != want {
			t.Fatalf("iteration %d: the walk found a chain=%v, a chain within %d entities exists=%v, graph %v", iteration, found, limit, want, hints)
		}
	}
}

func TestChainUpOne_SharedMemoMatchesReachabilityAcrossWalksOfOneRequest(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	graph := &swappableGraph{hints: map[string][]string{}}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		hs, ok := graph.get(node)
		if !ok || !strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			http.NotFound(w, r)
			return
		}
		ids := make([]model.EntityIdentifier, 0, len(hs))
		for _, h := range hs {
			ids = append(ids, model.EntityIdentifier(srv.URL+"/"+h))
		}
		self := model.EntityIdentifier(srv.URL + "/" + node)
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(createEntityStatement(t, self, self, ids, key, true)))
	}))
	t.Cleanup(srv.Close)

	const limit = 4
	rng := rand.New(rand.NewPCG(3, 4))
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: limit, MaxEntitiesTraversed: 10000}
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	for iteration := range 200 {
		nodes := 4 + rng.IntN(4)
		names := make([]string, nodes)
		for i := range names {
			names[i] = fmt.Sprintf("n%d", i)
		}
		candidates := append(append([]string{}, names...), "ta")
		hints := map[string][]string{"ta": nil}
		for _, node := range names {
			var hs []string
			for _, other := range candidates {
				if rng.IntN(3) == 0 {
					hs = append(hs, other)
				}
			}
			hints[node] = hs
		}
		graph.set(hints)

		cache := resolvecache.New()
		for _, start := range names {
			_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/"+start), anchor, nil, nil, nil, cache)
			found := err == nil && len(route) > 0
			want := reachableWithin(hints, start, "ta", limit, nil)
			if found != want {
				t.Fatalf("iteration %d: walking from %s on a cache shared with the earlier walks found a chain=%v, a chain within %d entities exists=%v, graph %v", iteration, start, found, limit, want, hints)
			}
		}
	}
}
