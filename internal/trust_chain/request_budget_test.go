package trust_chain

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func countingHintGraph(t *testing.T, hints map[string][]string, fetches *atomic.Int64) *httptest.Server {
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
		_, _ = w.Write([]byte(createEntityStatement(t, self, self, ids, key, true)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func deadEndGraph(leaves int) map[string][]string {
	hints := map[string][]string{}
	dead := make([]string, leaves)
	for i := range dead {
		dead[i] = fmt.Sprintf("d%d", i)
	}
	for i := range dead {
		hints[dead[i]] = dead
	}
	hints["leaf"] = dead
	hints["ta"] = nil
	return hints
}

func TestBuildTrustChain_SharesTheDeadEndMemoAcrossOneRequest(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, deadEndGraph(12), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client()}
	cache := resolvecache.New()

	leaf := model.EntityIdentifier(srv.URL + "/leaf")
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, cache); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}
	first := cache.Traversed()
	if first < 10 {
		t.Fatalf("this test only means something when the first walk explores the graph, it traversed %d entities", first)
	}

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, cache); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}
	second := cache.Traversed() - first

	if second != 0 {
		t.Errorf("the second walk of one request re-explored %d entities, so the dead ends are not remembered across the request (first walk: %d)", second, first)
	}
	if int64(first) <= fetches.Load() {
		t.Errorf("this graph is only re-explored when a node is visited by more than one path, got %d traversals for %d fetches", first, fetches.Load())
	}
}

func TestBuildTrustChain_BoundsTheEntitiesOneRequestTraverses(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, deadEndGraph(40), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: 8}

	leaf := model.EntityIdentifier(srv.URL + "/leaf")
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, resolvecache.New()); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}

	if got := fetches.Load(); got > int64(cfg.EntitiesTraversedLimit()) {
		t.Errorf("the request fetched %d entity configurations against a budget of %d", got, cfg.EntitiesTraversedLimit())
	}
}

func TestBuildTrustChain_TheBudgetSpansEveryWalkOfOneRequest(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, deadEndGraph(40), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: 8}
	cache := resolvecache.New()

	leaf := model.EntityIdentifier(srv.URL + "/leaf")
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	for range 5 {
		if _, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, cache); err == nil {
			t.Fatal("this graph reaches no trust anchor, so the walk must fail")
		}
	}

	if got := fetches.Load(); got > int64(cfg.EntitiesTraversedLimit()) {
		t.Errorf("five walks sharing one request fetched %d entity configurations against a budget of %d", got, cfg.EntitiesTraversedLimit())
	}
}

func TestConfiguration_BoundsAreOnByDefault(t *testing.T) {
	var cfg model.Configuration
	if cfg.TrustChainDepthLimit() != 10 {
		t.Errorf("expected a chain to be bounded at 10 entities by default, got %d", cfg.TrustChainDepthLimit())
	}
	if cfg.EntitiesTraversedLimit() != 256 {
		t.Errorf("expected a request to be bounded at 256 entities by default, got %d", cfg.EntitiesTraversedLimit())
	}
}

func TestBuildTrustChain_BoundsAWalkGivenNoCache(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, deadEndGraph(40), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: 8}

	leaf := model.EntityIdentifier(srv.URL + "/leaf")
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, nil); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}

	if got := fetches.Load(); got > int64(cfg.EntitiesTraversedLimit()) {
		t.Errorf("a caller passing no cache fetched %d entity configurations against a budget of %d", got, cfg.EntitiesTraversedLimit())
	}
}

func TestBuildTrustChain_TheDepthBoundAppliesWithoutConfiguration(t *testing.T) {
	hints := map[string][]string{"ta": nil}
	chain := []string{}
	for i := range 30 {
		node := fmt.Sprintf("n%d", i)
		chain = append(chain, node)
	}
	for i, node := range chain {
		if i+1 < len(chain) {
			hints[node] = []string{chain[i+1]}
			continue
		}
		hints[node] = []string{"ta"}
	}

	var fetches atomic.Int64
	srv := countingHintGraph(t, hints, &fetches)
	cfg := model.Configuration{HttpClient: srv.Client()}

	leaf := model.EntityIdentifier(srv.URL + "/" + chain[0])
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, leaf, anchor, resolvecache.New()); err == nil {
		t.Fatal("a chain of 31 entities is past the default depth bound and must be refused")
	}
	if got := fetches.Load(); got > 12 {
		t.Errorf("the default depth bound should stop the walk after about 10 entities, it fetched %d", got)
	}
}
