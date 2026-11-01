package trust_chain

import (
	"errors"
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

			resolved, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{HttpClient: client}, anchor, anchor, chain, resolvecache.New())
			if err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}
			if resolved.Exp != *expiry {
				t.Errorf("expected BuildTrustChain and ResolveMetadata to agree on the expiry, got %d and %d", *expiry, resolved.Exp)
			}
		})
	}
}

func TestBuildTrustChain_RefusesAChainWhoseExpiryHasPassed(t *testing.T) {
	tests := map[string]struct {
		subordinateExpiredFor time.Duration
	}{
		"a subordinate statement just past its exp":              {subordinateExpiredFor: time.Second},
		"a subordinate statement 30 seconds past its exp":        {subordinateExpiredFor: 30 * time.Second},
		"a subordinate statement near the edge of the allowance": {subordinateExpiredFor: model.ClockSkewLeeway - 5*time.Second},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			past := time.Now().Add(-tc.subordinateExpiredFor).Unix()
			client, leaf, anchor := federationWithClaims(t, "example.com", federationClaims{subordinate: map[string]any{"exp": past, "iat": past - 600}})
			chain, _, expiry, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, leaf, anchor, resolvecache.New())
			if err == nil {
				t.Fatalf("[10.4] a chain whose expiry has passed must be refused, got expiry %d (now %d)", *expiry, time.Now().Unix())
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[10.4] expected a chain whose expiry has passed to be invalid_trust_chain, got %v", err)
			}
			if chain != nil || expiry != nil {
				t.Errorf("[10.4] expected no chain alongside the refusal, got %d entries and expiry %v", len(chain), expiry)
			}
		})
	}
}
