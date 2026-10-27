package model

import (
	"testing"
	"time"
)

func TestDefaults_AreTheValuesTheReadmeDocuments(t *testing.T) {
	tests := map[string]struct {
		documented any
		actual     any
	}{
		"the peer deadline is 10s":         {documented: 10 * time.Second, actual: DefaultMaxPeerResponseTime},
		"the request byte budget is 64MiB": {documented: int64(64 << 20), actual: DefaultMaxRequestPeerBytes},
		"one response is capped at 1MiB":   {documented: int64(1 << 20), actual: DefaultMaxPeerResponseBytes},
		"a chain is 10 deep":               {documented: 10, actual: DefaultMaxTrustChainDepth},
		"a request fetches 1024 entities":  {documented: 1024, actual: DefaultMaxEntitiesTraversed},
		"a decoded value costs 256B":       {documented: 256, actual: DecodedValueCost},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.actual != tc.documented {
				t.Errorf("the README documents %v, got %v, so one of the two is wrong", tc.documented, tc.actual)
			}
		})
	}
}
