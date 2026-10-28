package trust_chain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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

func sharedDeadEndGraph(leaves int, selfHinting bool) map[string][]string {
	hints := map[string][]string{"ta": nil}
	dead := make([]string, leaves)
	for i := range dead {
		dead[i] = fmt.Sprintf("d%d", i)
	}
	for _, node := range dead {
		if selfHinting {
			hints[node] = []string{node}
			continue
		}
		hints[node] = nil
	}
	hints["subject"] = dead
	hints["issuer"] = dead
	return hints
}

func TestBuildTrustChain_RemembersDeadEndsAcrossTheWalksOfOneRequest(t *testing.T) {
	tests := []struct {
		name        string
		selfHinting bool
	}{
		{name: "dead ends with no authority hints"},
		{name: "dead ends whose only authority hint is themselves", selfHinting: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fetches atomic.Int64
			srv := countingHintGraph(t, sharedDeadEndGraph(12, tc.selfHinting), &fetches)
			cfg := model.Configuration{HttpClient: srv.Client()}
			cache := resolvecache.New()

			anchor := model.EntityIdentifier(srv.URL + "/ta")
			subject := model.EntityIdentifier(srv.URL + "/subject")
			issuer := model.EntityIdentifier(srv.URL + "/issuer")

			if _, _, _, err := BuildTrustChain(t.Context(), cfg, subject, anchor, cache); err == nil {
				t.Fatal("this graph reaches no trust anchor, so the walk must fail")
			}
			first := cache.Traversed()
			if first < 13 {
				t.Fatalf("the first walk must explore the whole graph for this test to mean anything, it stepped into %d entities", first)
			}

			if _, _, _, err := BuildTrustChain(t.Context(), cfg, issuer, anchor, cache); err == nil {
				t.Fatal("this graph reaches no trust anchor, so the walk must fail")
			}

			if second := cache.Traversed() - first; second != 1 {
				t.Errorf("the second walk of one request stepped into %d entities, expected only the issuer itself (first walk: %d)", second, first)
			}
			if got := fetches.Load(); got != 14 {
				t.Errorf("expected the 12 dead ends and the two leaves to be fetched once each, got %d fetches", got)
			}
		})
	}
}

func TestChainUpOne_ADeadEndThatDependedOnThePathIsNotRememberedForAnother(t *testing.T) {
	srv := hintGraphServer(t, map[string][]string{
		"subject": {"a"},
		"a":       {"c", "e"},
		"c":       {"a"},
		"e":       {"ta"},
		"issuer":  {"z"},
		"z":       {"c"},
		"ta":      nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client()}
	cache := resolvecache.New()

	anchor := model.EntityIdentifier(srv.URL + "/ta")

	_, route, _, err := ChainUpOne(context.Background(), cfg, model.EntityIdentifier(srv.URL+"/subject"), anchor, nil, nil, nil, cache)
	if err != nil || len(route) != 4 {
		t.Fatalf("expected the chain subject -> a -> e -> ta, got %d entries, err %v", len(route), err)
	}

	_, route, _, err = ChainUpOne(context.Background(), cfg, model.EntityIdentifier(srv.URL+"/issuer"), anchor, nil, nil, nil, cache)
	if err != nil || len(route) != 6 {
		t.Fatalf("expected the chain issuer -> z -> c -> a -> e -> ta, got %d entries, err %v", len(route), err)
	}
}

func TestChainUpOne_ADeadEndForOneTrustAnchorIsNotADeadEndForAnother(t *testing.T) {
	srv := hintGraphServer(t, map[string][]string{
		"leaf": {"a"},
		"a":    {"ta2"},
		"ta1":  nil,
		"ta2":  nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client()}
	cache := resolvecache.New()

	leaf := model.EntityIdentifier(srv.URL + "/leaf")

	if _, _, _, err := ChainUpOne(context.Background(), cfg, leaf, model.EntityIdentifier(srv.URL+"/ta1"), nil, nil, nil, cache); err == nil {
		t.Fatal("no path reaches ta1, so the walk must fail")
	}

	_, route, _, err := ChainUpOne(context.Background(), cfg, leaf, model.EntityIdentifier(srv.URL+"/ta2"), nil, nil, nil, cache)
	if err != nil || len(route) != 3 {
		t.Fatalf("expected the chain leaf -> a -> ta2, got %d entries, err %v", len(route), err)
	}
}

func TestBuildTrustChain_BoundsTheEntityConfigurationsOneRequestFetches(t *testing.T) {
	hints := sharedDeadEndGraph(40, false)
	for i := range 40 {
		hints[fmt.Sprintf("leaf%d", i)] = []string{fmt.Sprintf("d%d", i)}
	}

	var fetches atomic.Int64
	srv := countingHintGraph(t, hints, &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: 8}
	cache := resolvecache.New()

	anchor := model.EntityIdentifier(srv.URL + "/ta")
	for i := range 40 {
		if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(fmt.Sprintf("%s/leaf%d", srv.URL, i)), anchor, cache); err == nil {
			t.Fatal("this graph reaches no trust anchor, so the walk must fail")
		}
	}

	if got := fetches.Load(); got > int64(cfg.EntitiesTraversedLimit()) {
		t.Errorf("forty walks sharing one request fetched %d entity configurations against a budget of %d", got, cfg.EntitiesTraversedLimit())
	}
	if got := cache.Fetched(); got <= cfg.EntitiesTraversedLimit() {
		t.Errorf("the budget is only tested when the walks ask for more than it allows, they asked for %d", got)
	}
}

func TestBuildTrustChain_BoundsTheEntitiesOneRequestStepsInto(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, mutuallyHintingGraph(12), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client()}
	cache := resolvecache.New()

	_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/n0"), model.EntityIdentifier(srv.URL+"/ta"), cache)
	if err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}
	if !errors.Is(err, model.ErrLimitReached) {
		t.Errorf("expected a graph that outruns the step bound to be refused as a limit, got %v", err)
	}
	if got := cache.Traversed(); got > visitLimit(cfg)+1 {
		t.Errorf("the walk stepped into %d entities against a bound of %d", got, visitLimit(cfg))
	}
}

func TestBuildTrustChain_ALimitRefusalIsNotReportedAsAnUnreachableTrustAnchor(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(client *http.Client) model.Configuration
	}{
		{
			name: "the entity configurations one request may fetch",
			cfg: func(client *http.Client) model.Configuration {
				return model.Configuration{HttpClient: client, MaxEntitiesTraversed: 4}
			},
		},
		{
			name: "the entities one request may step into",
			cfg: func(client *http.Client) model.Configuration {
				return model.Configuration{HttpClient: client, MaxTrustChainDepth: 4, MaxEntitiesTraversed: 20}
			},
		},
		{
			name: "the entities on one path",
			cfg: func(client *http.Client) model.Configuration {
				return model.Configuration{HttpClient: client, MaxTrustChainDepth: 2}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fetches atomic.Int64
			srv := countingHintGraph(t, mutuallyHintingGraph(12), &fetches)
			cfg := tc.cfg(srv.Client())

			_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/n0"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New())
			if err == nil {
				t.Fatal("this graph reaches no trust anchor, so the walk must fail")
			}
			if !errors.Is(err, model.ErrLimitReached) {
				t.Errorf("expected the refusal to say a resolver limit was reached, got %v", err)
			}
			if !errors.Is(err, model.ErrInvalidTrustAnchor) {
				t.Errorf("expected a resolver limit to answer the code for a trust anchor that cannot be used, got %v", err)
			}
			if errors.Is(err, model.ErrServerError) || errors.Is(err, model.ErrTemporarilyUnavailable) {
				t.Error("a bound refusing a graph the caller named is neither a fault of this server nor a temporary condition")
			}

		})
	}
}

func TestConfiguration_BoundsAreOnByDefault(t *testing.T) {
	var cfg model.Configuration
	if cfg.TrustChainDepthLimit() != model.DefaultMaxTrustChainDepth {
		t.Errorf("expected a chain to be bounded by default, got %d", cfg.TrustChainDepthLimit())
	}
	if cfg.EntitiesTraversedLimit() != model.DefaultMaxEntitiesTraversed {
		t.Errorf("expected a request to be bounded by default, got %d", cfg.EntitiesTraversedLimit())
	}
	if visitLimit(cfg) != model.DefaultMaxTrustChainDepth*model.DefaultMaxEntitiesTraversed {
		t.Errorf("expected the step bound to be the product of the two, got %d", visitLimit(cfg))
	}
}

func TestVisitLimit_DoesNotOverflow(t *testing.T) {
	cfg := model.Configuration{MaxTrustChainDepth: 1 << 40, MaxEntitiesTraversed: 1 << 40}
	if got := visitLimit(cfg); got <= 0 {
		t.Errorf("expected a configuration whose product overflows to clamp, got %d", got)
	}
}

func TestBuildTrustChain_BoundsAWalkGivenNoCache(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, sharedDeadEndGraph(40, false), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: 8}

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+"/ta"), nil); err == nil {
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
		chain = append(chain, fmt.Sprintf("n%d", i))
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

func TestBuildTrustChain_TheFetchBoundAppliesWithoutConfiguration(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, sharedDeadEndGraph(model.DefaultMaxEntitiesTraversed, false), &fetches)
	cfg := model.Configuration{HttpClient: srv.Client(), MaxAuthorityHints: 2 * model.DefaultMaxEntitiesTraversed}

	_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New())
	if err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}
	if !errors.Is(err, model.ErrLimitReached) {
		t.Errorf("expected a graph wider than the default fetch bound to be refused as a limit, got %v", err)
	}
	if got := fetches.Load(); got != int64(model.DefaultMaxEntitiesTraversed) {
		t.Errorf("expected the default bound to stop the walk after %d fetches, it made %d", model.DefaultMaxEntitiesTraversed, got)
	}
}

func cliqueBeforeAValidRoute(size int) map[string][]string {
	names := make([]string, size)
	for i := range names {
		names[i] = fmt.Sprintf("c%d", i)
	}
	hints := map[string][]string{"ta": nil, "i": {"ta"}}
	for _, node := range names {
		others := []string{"leaf"}
		for _, other := range names {
			if other != node {
				others = append(others, other)
			}
		}
		hints[node] = others
	}
	hints["leaf"] = append(append([]string{}, names...), "i")
	return hints
}

func TestChainUpOne_ACliqueInFrontOfAValidRouteDoesNotExhaustTheStepBound(t *testing.T) {
	tests := []int{6, 8, 9}

	for _, size := range tests {
		t.Run(fmt.Sprintf("a clique of %d before the valid route", size), func(t *testing.T) {
			var fetches atomic.Int64
			srv := countingHintGraph(t, cliqueBeforeAValidRoute(size), &fetches)
			cfg := model.Configuration{HttpClient: srv.Client()}
			cache := resolvecache.New()

			_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, cache)
			if err != nil || len(route) != 3 {
				t.Fatalf("expected the chain leaf -> i -> ta past the clique, got %d entries, err %v", len(route), err)
			}
			if steps := cache.Traversed(); steps > 20*size {
				t.Errorf("a clique of %d cost %d steps, so its verdicts are not being reused within the walk", size, steps)
			}
		})
	}
}
