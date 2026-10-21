package model

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

type cacheRetriever struct {
	subordinate *SubordinateConfiguration
	err         error
	calls       int
}

func (r *cacheRetriever) GetSubordinate(context.Context, EntityIdentifier) (*SubordinateConfiguration, error) {
	r.calls++
	return r.subordinate, r.err
}

func (r *cacheRetriever) GetSubordinates(context.Context) (map[EntityIdentifier]*SubordinateConfiguration, error) {
	return nil, nil
}

func (r *cacheRetriever) GetSubordinateSigners(context.Context) ([]SignerConfiguration, error) {
	return nil, nil
}

func TestConfiguration_PeerResponseLimit(t *testing.T) {
	tests := []struct {
		name       string
		configured int64
		expect     int64
	}{
		{name: "zero applies the default", configured: 0, expect: DefaultMaxPeerResponseBytes},
		{name: "negative applies the default", configured: -1, expect: DefaultMaxPeerResponseBytes},
		{name: "an explicit value is honoured", configured: 4096, expect: 4096},
		{name: "the maximum is clamped so limit+1 cannot overflow", configured: math.MaxInt64, expect: math.MaxInt64 - 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Configuration{MaxPeerResponseBytes: tc.configured}
			if got := cfg.PeerResponseLimit(); got != tc.expect {
				t.Errorf("expected limit %d, got %d", tc.expect, got)
			}
			if limit := cfg.PeerResponseLimit(); limit+1 <= 0 {
				t.Errorf("limit+1 overflowed to %d", limit+1)
			}
		})
	}
}

func TestServerConfiguration_GetSubordinate(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	t.Run("a retriever returning nil without an error reports not found", func(t *testing.T) {
		retriever := &cacheRetriever{subordinate: nil, err: nil}
		cfg := ServerConfiguration{
			IntermediateConfiguration: &IntermediateConfiguration{},
			MetadataRetriever:         retriever,
		}

		subordinate, err := cfg.GetSubordinate(context.Background(), identifier)
		if err == nil {
			t.Fatalf("expected an error, got subordinate %v", subordinate)
		}
		if subordinate != nil {
			t.Errorf("expected no subordinate, got %v", subordinate)
		}
	})

	t.Run("the retriever's configuration is not mutated by caching", func(t *testing.T) {
		supplied := &SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "a"}}}}
		retriever := &cacheRetriever{subordinate: supplied}
		cfg := ServerConfiguration{
			IntermediateConfiguration: &IntermediateConfiguration{SubordinateCacheTime: time.Hour},
			MetadataRetriever:         retriever,
		}

		if _, err := cfg.GetSubordinate(context.Background(), identifier); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if supplied.CachedAt != 0 {
			t.Errorf("expected the retriever's own configuration to be untouched, got CachedAt %d", supplied.CachedAt)
		}

		if _, err := cfg.GetSubordinate(context.Background(), identifier); err != nil {
			t.Fatalf("expected no error on the cached lookup, got %v", err)
		}
		if retriever.calls != 1 {
			t.Errorf("expected the cached entry to be reused, got %d retriever calls", retriever.calls)
		}
	})
}

func TestIntermediateConfiguration_GetSubordinatesReturnsACopy(t *testing.T) {
	intermediate := &IntermediateConfiguration{SubordinateCacheTime: time.Hour}
	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

	supplied := &SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "a"}}}}
	intermediate.AddSubordinate("https://leaf.example.com", supplied)

	if supplied.CachedAt != 0 {
		t.Errorf("expected AddSubordinate not to mutate the caller's configuration, got CachedAt %d", supplied.CachedAt)
	}

	subordinates, err := cfg.GetSubordinates(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(subordinates) != 1 {
		t.Fatalf("expected one subordinate, got %d", len(subordinates))
	}

	for i := range 5 {
		subordinates[EntityIdentifier(fmt.Sprintf("https://injected-%d.example.com", i))] = supplied
	}

	again, err := cfg.GetSubordinates(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(again) != 1 {
		t.Errorf("expected writes to the returned map not to reach the cache, got %d subordinates", len(again))
	}
}

func TestConfiguration_TrustMarkIssuerLimit(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		expect     int
	}{
		{name: "zero applies the default", configured: 0, expect: DefaultMaxTrustMarkIssuers},
		{name: "negative applies the default", configured: -1, expect: DefaultMaxTrustMarkIssuers},
		{name: "an explicit value is honoured", configured: 4, expect: 4},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Configuration{MaxTrustMarkIssuers: tc.configured}
			if got := cfg.TrustMarkIssuerLimit(); got != tc.expect {
				t.Errorf("expected limit %d, got %d", tc.expect, got)
			}
		})
	}

	t.Run("the default admits a realistic number of accreditations", func(t *testing.T) {
		if DefaultMaxTrustMarkIssuers < 32 {
			t.Errorf("a subject with a few dozen trust mark issuers must resolve without configuration, so the default must not drop below 32, got %d", DefaultMaxTrustMarkIssuers)
		}
	})
}

func TestConfiguration_WalkLimits(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		depth      int
		entities   int
	}{
		{name: "zero applies the defaults", configured: 0, depth: DefaultMaxTrustChainDepth, entities: DefaultMaxEntitiesTraversed},
		{name: "negative applies the defaults", configured: -1, depth: DefaultMaxTrustChainDepth, entities: DefaultMaxEntitiesTraversed},
		{name: "an explicit value is honoured", configured: 3, depth: 3, entities: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Configuration{MaxTrustChainDepth: tc.configured, MaxEntitiesTraversed: tc.configured}
			if got := cfg.TrustChainDepthLimit(); got != tc.depth {
				t.Errorf("expected a depth limit of %d, got %d", tc.depth, got)
			}
			if got := cfg.EntitiesTraversedLimit(); got != tc.entities {
				t.Errorf("expected an entity limit of %d, got %d", tc.entities, got)
			}
		})
	}
}
