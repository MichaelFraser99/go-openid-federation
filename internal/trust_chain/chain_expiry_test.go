package trust_chain

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestBuildTrustChain_TheExpiryIsTheEarliestInTheWholeChain(t *testing.T) {
	now := time.Now().UTC()
	soon, later, latest := now.Add(10*time.Minute).Unix(), now.Add(time.Hour).Unix(), now.Add(2*time.Hour).Unix()

	tests := map[string]struct {
		leafExp, subordinateExp, anchorExp int64
		expect                             int64
		expectErr                          string
	}{
		"the subordinate statement expires first":            {leafExp: later, subordinateExp: soon, anchorExp: latest, expect: soon},
		"only the leaf's configuration expires first":        {leafExp: soon, subordinateExp: latest, anchorExp: later, expect: soon},
		"only the anchor's configuration expires first":      {leafExp: later, subordinateExp: latest, anchorExp: soon, expect: soon},
		"an expired subordinate statement refuses the chain": {leafExp: later, subordinateExp: now.Add(-10 * time.Second).Unix(), anchorExp: later, expectErr: "failed to retrieve a usable subordinate statement"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client, leaf, anchor := federationWithClaims(t, "example.com", federationClaims{
				leaf:        map[string]any{"exp": tc.leafExp},
				subordinate: map[string]any{"exp": tc.subordinateExp},
				anchor:      map[string]any{"exp": tc.anchorExp},
			})
			chain, _, expiry, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, leaf, anchor, resolvecache.New())
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[10.4] expected a chain holding an expired statement to be refused with %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the chain to build, got %v", err)
			}
			if *expiry != tc.expect {
				t.Errorf("[10.4] expected the minimum exp within the chain, %d, got %d", tc.expect, *expiry)
			}

			resolved, err := ResolveMetadata(t.Context(), model.Configuration{HttpClient: client}, anchor, anchor, chain, resolvecache.New())
			if err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}
			if resolved.Exp != *expiry {
				t.Errorf("expected BuildTrustChain and ResolveMetadata to agree on the expiry, got %d and %d", *expiry, resolved.Exp)
			}
		})
	}
}
