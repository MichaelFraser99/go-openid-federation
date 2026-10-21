package trust_chain

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"crypto/rand"
	"crypto/rsa"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type nodeFetchLog struct {
	mu     sync.Mutex
	counts map[string]int
}

func (l *nodeFetchLog) get(node string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[node]
}

func loggingHintGraph(t *testing.T, hints map[string][]string) (*httptest.Server, *nodeFetchLog) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	log := &nodeFetchLog{counts: map[string]int{}}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		log.mu.Lock()
		log.counts[node]++
		log.mu.Unlock()
		hs, ok := hints[node]
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
	return srv, log
}

func linearChainGraph(entities int) map[string][]string {
	hints := map[string][]string{"ta": nil}
	for i := range entities - 1 {
		next := "ta"
		if i+1 < entities-1 {
			next = fmt.Sprintf("n%d", i+1)
		}
		hints[fmt.Sprintf("n%d", i)] = []string{next}
	}
	return hints
}

func TestChainUpOne_TheDepthBoundIsExact(t *testing.T) {
	tests := []struct {
		entities int
		limit    int
		refused  bool
	}{
		{entities: 3, limit: 3},
		{entities: 4, limit: 3, refused: true},
		{entities: 10, limit: 0},
		{entities: 11, limit: 0, refused: true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d entities against a limit of %d", tc.entities, tc.limit), func(t *testing.T) {
			srv, _ := loggingHintGraph(t, linearChainGraph(tc.entities))
			cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: tc.limit}

			_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/n0"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
			if tc.refused {
				if !errors.Is(err, model.ErrLimitReached) {
					t.Fatalf("a chain of %d entities is one past the bound and must be refused as a limit, got %d entries, err %v", tc.entities, len(route), err)
				}
				return
			}
			if err != nil || len(route) != tc.entities {
				t.Fatalf("a chain of %d entities is within the bound, got %d entries, err %v", tc.entities, len(route), err)
			}
		})
	}
}

func TestChainUpOne_TheFetchBoundIsExact(t *testing.T) {
	tests := []struct {
		dead    int
		budget  int
		refused bool
	}{
		{dead: 7, budget: 8},
		{dead: 8, budget: 8, refused: true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d dead ends against a budget of %d", tc.dead, tc.budget), func(t *testing.T) {
			srv, _ := loggingHintGraph(t, sharedDeadEndGraph(tc.dead, false))
			cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: tc.budget}

			_, _, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
			if err == nil {
				t.Fatal("this graph reaches no trust anchor, so the walk must fail")
			}
			if got := errors.Is(err, model.ErrLimitReached); got != tc.refused {
				t.Fatalf("%d fetches against a budget of %d: expected limit=%v, got %v", tc.dead+1, tc.budget, tc.refused, err)
			}
		})
	}
}

func TestChainUpOne_AWalkNeedingExactlyTheStepBoundSucceeds(t *testing.T) {
	srv, _ := loggingHintGraph(t, cliqueBeforeAValidRoute(6))
	leaf := model.EntityIdentifier(srv.URL + "/leaf")
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	probe := resolvecache.New()
	if _, _, _, err := ChainUpOne(t.Context(), model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: 3, MaxEntitiesTraversed: 1000}, leaf, anchor, nil, nil, nil, probe); err != nil {
		t.Fatalf("the probe walk must succeed, got %v", err)
	}
	steps, fetched := probe.Traversed(), probe.Fetched()
	if steps < 2 || fetched < 2 {
		t.Fatalf("the probe measured %d steps and %d fetches, which is too small to bound anything", steps, fetched)
	}

	budget := (steps + 2) / 3
	if budget < fetched {
		budget = fetched
	}
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: 3, MaxEntitiesTraversed: budget}
	if _, route, _, err := ChainUpOne(t.Context(), cfg, leaf, anchor, nil, nil, nil, resolvecache.New()); err != nil || len(route) != 3 {
		t.Fatalf("a walk needing %d steps must succeed against a step bound of 3 x %d, got %d entries, err %v", steps, budget, len(route), err)
	}
}

func TestChainUpOne_ADepthRefusalTwoLevelsDownIsNotRememberedAsADeadEnd(t *testing.T) {
	srv, _ := loggingHintGraph(t, map[string][]string{
		"leaf": {"a", "p"},
		"a":    {"b"},
		"b":    {"p"},
		"p":    {"q"},
		"q":    {"ta"},
		"ta":   nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: 5}

	_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
	if err != nil || len(route) != 4 {
		t.Fatalf("expected the chain leaf -> p -> q -> ta once the longer path is refused for depth, got %d entries, err %v", len(route), err)
	}
}

func TestChainUpOne_AnUnreachableTrustAnchorIsFetchedOncePerRequest(t *testing.T) {
	srv, log := loggingHintGraph(t, map[string][]string{
		"leaf": {"a", "b"},
		"a":    {"ta"},
		"b":    {"ta"},
	})
	cfg := model.Configuration{HttpClient: srv.Client()}

	if _, _, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New()); err == nil {
		t.Fatal("the trust anchor does not answer, so the walk must fail")
	}
	if got := log.get("ta"); got != 1 {
		t.Errorf("a trust anchor that failed once is a dead end for the rest of the request, it was fetched %d times", got)
	}
}

func TestChainUpOne_ARememberedDeadEndAtTheDepthBoundIsNotALimit(t *testing.T) {
	srv, _ := loggingHintGraph(t, map[string][]string{
		"leaf": {"x", "a"},
		"x":    nil,
		"a":    {"b"},
		"b":    {"x"},
		"ta":   nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: 3}

	_, _, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
	if err == nil {
		t.Fatal("no path reaches the trust anchor, so the walk must fail")
	}
	if errors.Is(err, model.ErrLimitReached) {
		t.Fatalf("every path ends at a proven dead end, so the trust anchor is unreachable rather than a limit, got %v", err)
	}
}

func TestChainUpOne_ARememberedDeadEndCostsNoStep(t *testing.T) {
	srv, _ := loggingHintGraph(t, map[string][]string{
		"leaf": {"d"},
		"ta":   nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client()}
	cache := resolvecache.New()
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), anchor, nil, nil, nil, cache); err == nil {
		t.Fatal("d does not answer, so the walk must fail")
	}
	before := cache.Traversed()
	if _, _, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/d"), anchor, nil, nil, nil, cache); err == nil {
		t.Fatal("d is a dead end, so a walk from it must fail")
	}
	if got := cache.Traversed() - before; got != 0 {
		t.Errorf("a walk starting at a remembered dead end stepped into %d entities, expected none", got)
	}
}

func TestChainUpOne_ACacheHitIsNotChargedAsAFetch(t *testing.T) {
	srv, _ := loggingHintGraph(t, map[string][]string{
		"leaf": {"a", "b"},
		"a":    {"leaf"},
		"b":    {"a", "c"},
		"c":    {"ta"},
		"ta":   nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client(), MaxEntitiesTraversed: 5}

	_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
	if err != nil || len(route) != 4 {
		t.Fatalf("five distinct entities fit a fetch budget of five even though a is revisited from the cache, got %d entries, err %v", len(route), err)
	}
}

func TestConfiguration_TheDocumentedDefaultsAreTheOnesInUse(t *testing.T) {
	if model.DefaultMaxTrustChainDepth != 10 {
		t.Errorf("the README documents a default depth of 10, the code uses %d", model.DefaultMaxTrustChainDepth)
	}
	if model.DefaultMaxEntitiesTraversed != 1024 {
		t.Errorf("the README documents a default fetch bound of 1024, the code uses %d", model.DefaultMaxEntitiesTraversed)
	}
	if want := (model.DefaultMaxTrustMarkIssuers + 1) * model.DefaultMaxTrustChainDepth; model.DefaultMaxEntitiesTraversed < want {
		t.Errorf("the fetch bound must cover a subject walk and %d issuer walks of %d entities, which needs %d, the default is %d", model.DefaultMaxTrustMarkIssuers, model.DefaultMaxTrustChainDepth, want, model.DefaultMaxEntitiesTraversed)
	}
}

func TestChainUpOne_ADepthRefusalReusedWithinAWalkIsNotRememberedForAnother(t *testing.T) {
	srv, _ := loggingHintGraph(t, map[string][]string{
		"subject": {"b", "c"},
		"b":       {"d"},
		"c":       {"d"},
		"d":       {"ta"},
		"ta":      nil,
	})
	cfg := model.Configuration{HttpClient: srv.Client(), MaxTrustChainDepth: 3}
	cache := resolvecache.New()
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), anchor, nil, nil, nil, cache); err == nil {
		t.Fatal("every chain from subject is longer than three entities, so the walk must fail")
	}

	_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/c"), anchor, nil, nil, nil, cache)
	if err != nil || len(route) != 3 {
		t.Fatalf("expected the chain c -> d -> ta, got %d entries, err %v", len(route), err)
	}
}
