package model

import (
	"context"
	"errors"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func TestServerConfiguration_GetSubordinate_AnInMemorySubordinateIsNotACache(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	tests := []struct {
		name      string
		cacheTime time.Duration
	}{
		{name: "a zero cache time", cacheTime: 0},
		{name: "a cache time of one nanosecond", cacheTime: time.Nanosecond},
		{name: "a negative cache time", cacheTime: -time.Hour},
		{name: "a cache time of an hour", cacheTime: time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intermediate := &IntermediateConfiguration{SubordinateCacheTime: tc.cacheTime}
			intermediate.AddSubordinate(identifier, &SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "a"}}}})
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

			for range 2 {
				subordinate, err := cfg.GetSubordinate(context.Background(), identifier)
				if err != nil {
					t.Fatalf("with no retriever to refill it, a subordinate added in memory must be served however old it is, got %v", err)
				}
				if subordinate == nil || len(subordinate.JWKs.Keys) != 1 {
					t.Fatalf("expected the subordinate that was added, got %v", subordinate)
				}
			}
		})
	}

	t.Run("an identifier that was never added is not found", func(t *testing.T) {
		cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{}}
		if _, err := cfg.GetSubordinate(context.Background(), identifier); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not found, got %v", err)
		}
	})

	t.Run("FlushCache removes it, since with no retriever the map is the only store", func(t *testing.T) {
		intermediate := &IntermediateConfiguration{}
		intermediate.AddSubordinate(identifier, &SubordinateConfiguration{})
		intermediate.FlushCache()
		cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
		if _, err := cfg.GetSubordinate(context.Background(), identifier); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not found after FlushCache, got %v", err)
		}
	})
}

func TestServerConfiguration_GetSubordinate_ARetrieverResultIsCachedForTheCacheTime(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	tests := []struct {
		name      string
		cacheTime time.Duration
		calls     int
	}{
		{name: "an entry older than the cache time is fetched again", cacheTime: 0, calls: 1},
		{name: "an entry within the cache time is reused", cacheTime: time.Hour, calls: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			retriever := &cacheRetriever{subordinate: &SubordinateConfiguration{}}
			intermediate := &IntermediateConfiguration{SubordinateCacheTime: tc.cacheTime}
			intermediate.AddSubordinate(identifier, &SubordinateConfiguration{})
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate, MetadataRetriever: retriever}

			if _, err := cfg.GetSubordinate(context.Background(), identifier); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if retriever.calls != tc.calls {
				t.Errorf("expected %d retriever calls, got %d", tc.calls, retriever.calls)
			}
		})
	}
}
