package trust_chain

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func mutuallyHintingGraph(size int) map[string][]string {
	names := make([]string, 0, size)
	for i := range size {
		names = append(names, fmt.Sprintf("n%d", i))
	}
	hints := map[string][]string{}
	for _, node := range names {
		others := make([]string, 0, size-1)
		for _, other := range names {
			if other != node {
				others = append(others, other)
			}
		}
		hints[node] = others
	}
	return hints
}

func TestBuildTrustChain_DenseGraphIsWalkedInBoundedTime(t *testing.T) {
	tests := []struct {
		name  string
		nodes int
	}{
		{name: "nine mutually hinting entities", nodes: 9},
		{name: "twelve mutually hinting entities", nodes: 12},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp := newTopo(t, mutuallyHintingGraph(tc.nodes))
			cfg := model.Configuration{HttpClient: tp.server.Client()}

			start := time.Now()
			_, _, _, err := BuildTrustChain(context.Background(), cfg, tp.id["n0"], model.EntityIdentifier("https://unreachable.example.com"), resolvecache.New())
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("expected no chain to an unreachable trust anchor")
			}
			if elapsed > 20*time.Second {
				t.Errorf("walk over %d mutually hinting entities took %s, expected under 20s", tc.nodes, elapsed)
			}
			if hits := tp.maxHits(); hits > 1 {
				t.Errorf("expected each entity configuration to be fetched at most once, got %d for one entity", hits)
			}
		})
	}
}

func TestBuildTrustChain_WalkStopsWhenContextIsCancelled(t *testing.T) {
	tp := newTopo(t, mutuallyHintingGraph(14))
	cfg := model.Configuration{HttpClient: tp.server.Client()}

	cache := resolvecache.New()
	for node := range tp.keys {
		signed, statement, err := entity_configuration.Retrieve(context.Background(), cfg, tp.id[node], cache)
		if err != nil {
			t.Fatalf("failed to pre-warm %q: %v", node, err)
		}
		cache.Store(tp.id[node], signed, statement)
	}

	tp.mu.Lock()
	warmHits := 0
	for _, hits := range tp.hits {
		warmHits += hits
	}
	tp.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, _, _, err := BuildTrustChain(ctx, cfg, tp.id["n0"], model.EntityIdentifier("https://unreachable.example.com"), cache)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the cancelled walk to fail")
	}
	if elapsed > 10*time.Second {
		t.Errorf("walk continued for %s after the context was cancelled", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected the context cause to be preserved, got %v", err)
	}
	if !errors.Is(err, model.ErrTemporarilyUnavailable) {
		t.Errorf("expected a temporarily_unavailable error so the endpoint answers 503, got %v", err)
	}

	tp.mu.Lock()
	totalHits := 0
	for _, hits := range tp.hits {
		totalHits += hits
	}
	tp.mu.Unlock()
	if totalHits != warmHits {
		t.Errorf("expected the cancelled walk to make no further fetches, got %d extra", totalHits-warmHits)
	}
}
