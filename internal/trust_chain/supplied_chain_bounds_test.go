package trust_chain

import (
	"errors"
	"math"
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
			_, err := resolveTrustingSuppliedAnchor(t, t.Context(), cfg, "https://resolver.example.com", "https://ta.example.com", tc.chain, resolvecache.New())
			if !errors.Is(err, model.ErrInvalidTrustChain) || errors.Is(err, model.ErrLimitReached) {
				t.Fatalf("expected an invalid_trust_chain refusal, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected a refusal containing %q, got %v", tc.expected, err)
			}
		})
	}
}

func TestResolveMetadata_ASuppliedChainIsHeldToTheDepthAWalkIsHeldTo(t *testing.T) {
	tests := map[string]struct {
		entities     int
		depth        int
		omitAnchor   bool
		expectRefuse string
	}{
		"two entities at a depth of two":                         {entities: 2, depth: 2},
		"three entities at a depth of three":                     {entities: 3, depth: 3},
		"five entities at a depth of five":                       {entities: 5, depth: 5},
		"four entities at a depth of three":                      {entities: 4, depth: 3, expectRefuse: "the trust chain holds 5 entries, more than the 4"},
		"four entities without the anchor at a depth of four":    {entities: 4, depth: 4, omitAnchor: true},
		"four entities without the anchor at a depth of three":   {entities: 4, depth: 3, omitAnchor: true, expectRefuse: "the trust chain holds 4 entries without the trust anchor's entity configuration, more than the 3"},
		"four entities at an unlimited depth":                    {entities: 4, depth: math.MaxInt},
		"four entities without the anchor at an unlimited depth": {entities: 4, depth: math.MaxInt, omitAnchor: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tp := newTopo(t, linearChainGraph(tc.entities))
			built := model.Configuration{HttpClient: tp.server.Client(), MaxTrustChainDepth: tc.entities}

			chain, _, _, err := BuildTrustChain(t.Context(), built, tp.id["n0"], tp.id["ta"], resolvecache.New())
			if err != nil {
				t.Fatalf("failed to build the chain: %v", err)
			}
			if len(chain) != tc.entities+1 {
				t.Fatalf("expected the built chain to hold %d entries, it holds %d", tc.entities+1, len(chain))
			}
			if tc.omitAnchor {
				chain = chain[:len(chain)-1]
			}

			cfg := model.Configuration{HttpClient: tp.server.Client(), MaxTrustChainDepth: tc.depth}
			_, err = resolveTrustingSuppliedAnchor(t, t.Context(), cfg, tp.id["n0"], tp.id["ta"], chain, resolvecache.New())
			if tc.expectRefuse == "" {
				if err != nil {
					t.Fatalf("expected a chain of %d entities to resolve at a depth of %d, got %v", tc.entities, tc.depth, err)
				}
				return
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) || !strings.Contains(err.Error(), tc.expectRefuse) {
				t.Fatalf("expected an invalid_trust_chain refusal containing %q, got %v", tc.expectRefuse, err)
			}
		})
	}
}
