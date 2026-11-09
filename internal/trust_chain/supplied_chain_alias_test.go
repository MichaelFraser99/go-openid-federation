package trust_chain

import (
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_LeavesTheCallersChainAsItWas(t *testing.T) {
	const untouched = "THE-CALLERS-OWN-ENTRY"
	tp := newTopo(t, map[string][]string{
		"leaf": {"ta"},
		"ta":   {},
	})
	cfg := model.Configuration{HttpClient: tp.server.Client()}

	leafEC := createEntityStatement(t, tp.id["leaf"], tp.id["leaf"], []model.EntityIdentifier{tp.id["ta"]}, tp.keys["leaf"], false)
	subordinateStatement := createSubordinateStatement(t, tp.id["ta"], tp.id["leaf"], tp.keys["ta"], tp.keys["leaf"].Public())
	anchorEC := createEntityStatement(t, tp.id["ta"], tp.id["ta"], nil, tp.keys["ta"], true)

	tests := []struct {
		name       string
		subject    string
		backing    []string
		supplied   int
		holdAnchor bool
	}{
		{name: "a chain with the trust anchor omitted, passed with spare capacity", subject: "leaf", backing: []string{leafEC, subordinateStatement, untouched}, supplied: 2, holdAnchor: true},
		{name: "a chain ending in the trust anchor's configuration, with no keys held for it", subject: "leaf", backing: []string{leafEC, subordinateStatement, anchorEC, untouched}, supplied: 3},
		{name: "the trust anchor's own configuration alone, with no keys held for it", subject: "ta", backing: []string{anchorEC, untouched}, supplied: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.backing)
			supplied := tc.backing[:tc.supplied]

			var err error
			if tc.holdAnchor {
				_, err = resolveTrustingSuppliedAnchor(t, t.Context(), cfg, tp.id[tc.subject], tp.id["ta"], supplied, resolvecache.New())
			} else {
				_, err = ResolveMetadata(t.Context(), cfg, tp.id[tc.subject], tp.id["ta"], supplied, resolvecache.New())
			}
			if err != nil {
				t.Fatalf("expected the chain to resolve, got %v", err)
			}

			for i := range before {
				if tc.backing[i] != before[i] {
					t.Errorf("resolution wrote into the caller's array at entry %d: it held %.40q and now holds %.40q", i, before[i], tc.backing[i])
				}
			}
		})
	}
}
