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
	tests := map[string]struct {
		subordinateExp int64
		expectSelf     bool
		expectErr      string
	}{
		"the subordinate statement expires first":            {subordinateExp: now.Add(10 * time.Minute).Unix(), expectSelf: true},
		"the entity configurations expire first":             {subordinateExp: now.Add(2 * time.Hour).Unix()},
		"an expired subordinate statement refuses the chain": {subordinateExp: now.Add(-10 * time.Second).Unix(), expectErr: "failed to retrieve a usable subordinate statement"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client, leaf, anchor := federationWithSubordinateClaims(t, "example.com", map[string]any{"exp": tc.subordinateExp})
			chain, parsed, expiry, err := BuildTrustChain(t.Context(), model.Configuration{HttpClient: client}, leaf, anchor, resolvecache.New())
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[10.4] expected a chain holding an expired statement to be refused with %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the chain to build, got %v", err)
			}

			earliest := parsed[0].Exp
			for _, statement := range parsed[1:] {
				earliest = min(earliest, statement.Exp)
			}
			if *expiry != earliest {
				t.Errorf("[10.4] expected the minimum exp within the chain, %d, got %d", earliest, *expiry)
			}
			if tc.expectSelf != (*expiry == tc.subordinateExp) {
				t.Errorf("[10.4] expected the subordinate statement's exp to decide the expiry: %v, got expiry %d against its exp %d", tc.expectSelf, *expiry, tc.subordinateExp)
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
