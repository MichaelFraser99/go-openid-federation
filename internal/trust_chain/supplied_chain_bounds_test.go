package trust_chain

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_ASuppliedChainIsBoundedBeforeAnyEntryIsDecoded(t *testing.T) {
	padding := make([]any, 200)
	for i := range padding {
		padding[i] = 0
	}
	small := unsignedStatement(t, map[string]any{"iss": "https://ta.example.com", "sub": "https://leaf.example.com"})
	padded := unsignedStatement(t, map[string]any{"iss": "https://ta.example.com", "sub": "https://leaf.example.com", "pad": padding})
	cfg := model.Configuration{MaxStatementValues: 100, MaxTrustChainDepth: 3}

	tests := map[string]struct {
		chain    []string
		expected string
	}{
		"a padded final entry":   {chain: []string{small, small, padded}, expected: "trust chain entry 2 has a body that holds more than the 100 JSON values"},
		"a padded first entry":   {chain: []string{padded, small, small}, expected: "trust chain entry 0 has a body that holds more than the 100 JSON values"},
		"a padded middle entry":  {chain: []string{small, padded, small}, expected: "trust chain entry 1 has a body that holds more than the 100 JSON values"},
		"one entry past the cap": {chain: []string{small, small, small, small, small}, expected: "the trust chain holds 5 entries, more than the 4 this resolver will process"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveMetadata(t.Context(), cfg, "https://resolver.example.com", "https://ta.example.com", tc.chain, resolvecache.New())
			if !errors.Is(err, model.ErrInvalidTrustChain) || errors.Is(err, model.ErrLimitReached) {
				t.Fatalf("expected an invalid_trust_chain refusal, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected a refusal containing %q, got %v", tc.expected, err)
			}
		})
	}
}

func TestResolveMetadata_TheLongestChainThisResolverBuildsIsNotRefusedForItsLength(t *testing.T) {
	tests := []int{2, 3, 5}

	for _, depth := range tests {
		t.Run(fmt.Sprintf("a chain of %d entities", depth), func(t *testing.T) {
			tp := newTopo(t, linearChainGraph(depth))
			cfg := model.Configuration{HttpClient: tp.server.Client(), MaxTrustChainDepth: depth}

			chain, _, _, err := BuildTrustChain(t.Context(), cfg, tp.id["n0"], tp.id["ta"], resolvecache.New())
			if err != nil {
				t.Fatalf("failed to build the chain: %v", err)
			}
			if len(chain) != depth+1 {
				t.Fatalf("expected the built chain to hold %d entries, it holds %d", depth+1, len(chain))
			}
			if _, err := ResolveMetadata(t.Context(), cfg, tp.id["n0"], tp.id["ta"], chain, resolvecache.New()); err != nil {
				t.Fatalf("expected the chain this resolver built to resolve, got %v", err)
			}
		})
	}
}
