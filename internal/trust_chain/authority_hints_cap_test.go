package trust_chain

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func hostileBeforeAValidRoute(hostileHints int) map[string][]string {
	hints := map[string][]string{"ta": nil, "good": {"ta"}, "leaf": {"hostile", "good"}}
	listed := []string{"ta"}
	for i := 1; i < hostileHints; i++ {
		node := fmt.Sprintf("h%d", i)
		hints[node] = nil
		listed = append(listed, node)
	}
	hints["hostile"] = listed
	return hints
}

func TestChainUpOne_ASuperiorListingTooManyAuthorityHintsIsADeadEnd(t *testing.T) {
	tests := map[string]struct {
		cfg          model.Configuration
		hostileHints int
		expectVia    string
	}{
		"a superior at the default is walked":             {hostileHints: model.DefaultMaxAuthorityHints, expectVia: "hostile"},
		"a superior past the default is passed by":        {hostileHints: model.DefaultMaxAuthorityHints + 1, expectVia: "good"},
		"a superior at a configured limit is walked":      {cfg: model.Configuration{MaxAuthorityHints: 3}, hostileHints: 3, expectVia: "hostile"},
		"a superior past a configured limit is passed by": {cfg: model.Configuration{MaxAuthorityHints: 3}, hostileHints: 4, expectVia: "good"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var fetches atomic.Int64
			srv := countingHintGraph(t, hostileBeforeAValidRoute(tc.hostileHints), &fetches)
			cfg := tc.cfg
			cfg.HttpClient = srv.Client()

			_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
			if err != nil || len(route) != 3 {
				t.Fatalf("expected a chain of three entries, got %d entries, err %v", len(route), err)
			}
			if via := strings.TrimPrefix(string(route[1].Sub), srv.URL+"/"); via != tc.expectVia {
				t.Errorf("expected the chain to pass through %q, it passed through %q", tc.expectVia, via)
			}
		})
	}
}

func TestBuildTrustChain_ASubjectListingTooManyAuthorityHintsIsRefusedNamingTheBound(t *testing.T) {
	var fetches atomic.Int64
	hints := hostileBeforeAValidRoute(model.DefaultMaxAuthorityHints + 1)
	hints["subject"] = hints["hostile"]
	srv := countingHintGraph(t, hints, &fetches)
	cfg := model.Configuration{HttpClient: srv.Client()}

	_, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New())
	if !errors.Is(err, model.ErrInvalidTrustChain) || errors.Is(err, model.ErrInvalidTrustAnchor) || errors.Is(err, model.ErrLimitReached) {
		t.Fatalf("expected the subject to be refused as an invalid trust chain rather than a walk bound, got %v", err)
	}
	expected := fmt.Sprintf("lists %d authority_hints, more than the %d this resolver will inspect", model.DefaultMaxAuthorityHints+1, model.DefaultMaxAuthorityHints)
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected the refusal to name the bound with %q, got %v", expected, err)
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("expected only the subject's own configuration to be fetched, %d were", got)
	}
}

func TestBuildTrustChain_AnAnchorListingTooManyAuthorityHintsIsStillReached(t *testing.T) {
	tests := map[string]model.Configuration{
		"at the default":        {},
		"at a configured limit": {MaxAuthorityHints: 3},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			var fetches atomic.Int64
			hints := map[string][]string{"leaf": {"ta"}}
			for i := range max(cfg.AuthorityHintsLimit()+1, model.DefaultMaxAuthorityHints+1) {
				hints["ta"] = append(hints["ta"], fmt.Sprintf("above%d", i))
			}
			srv := countingHintGraph(t, hints, &fetches)
			cfg.HttpClient = srv.Client()

			_, route, _, err := ChainUpOne(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, resolvecache.New())
			if err != nil || len(route) != 2 {
				t.Fatalf("expected the chain leaf -> ta, got %d entries, err %v", len(route), err)
			}
		})
	}
}

func TestChainUpOne_ASuperiorOverTheCapIsSteppedIntoOnce(t *testing.T) {
	var fetches atomic.Int64
	hints := hostileBeforeAValidRoute(model.DefaultMaxAuthorityHints + 1)
	hints["a"] = []string{"hostile"}
	hints["b"] = []string{"hostile"}
	hints["c"] = []string{"hostile"}
	hints["leaf"] = []string{"a", "b", "good"}
	srv := countingHintGraph(t, hints, &fetches)
	cache := resolvecache.New()

	_, route, _, err := ChainUpOne(t.Context(), model.Configuration{HttpClient: srv.Client()}, model.EntityIdentifier(srv.URL+"/leaf"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, cache)
	if err != nil || len(route) != 3 {
		t.Fatalf("expected the chain leaf -> good -> ta, got %d entries, err %v", len(route), err)
	}
	if steps := cache.Traversed(); steps != 6 {
		t.Errorf("expected six steps, leaf, a, hostile, b, good and ta, the walk took %d, so the superior over the cap was stepped into again", steps)
	}

	_, _, _, err = ChainUpOne(t.Context(), model.Configuration{HttpClient: srv.Client()}, model.EntityIdentifier(srv.URL+"/c"), model.EntityIdentifier(srv.URL+"/ta"), nil, nil, nil, cache)
	if err == nil {
		t.Fatalf("expected no route from c, whose only superior is over the cap")
	}
	if steps := cache.Traversed(); steps != 7 {
		t.Errorf("expected a later walk sharing the request to step only into c, it took %d steps in total, so the superior over the cap was stepped into again", steps)
	}
}
