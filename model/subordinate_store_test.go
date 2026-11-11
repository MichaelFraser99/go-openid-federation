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

func TestServerConfiguration_GetSubordinateJWKs_InMemorySignersAreOrderedBySubject(t *testing.T) {
	tests := []struct {
		name     string
		added    []EntityIdentifier
		expected []string
	}{
		{name: "added in order", added: []EntityIdentifier{"https://a.example.com", "https://b.example.com", "https://c.example.com"}, expected: []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"}},
		{name: "added in reverse", added: []EntityIdentifier{"https://c.example.com", "https://b.example.com", "https://a.example.com"}, expected: []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"}},
		{name: "added out of order with one subordinate that has no signer", added: []EntityIdentifier{"https://b.example.com", "https://unsigned.example.com", "https://a.example.com"}, expected: []string{"https://a.example.com", "https://b.example.com"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intermediate := &IntermediateConfiguration{}
			for _, identifier := range tc.added {
				subordinate := &SubordinateConfiguration{}
				if identifier != "https://unsigned.example.com" {
					subordinate.SignerConfiguration = &SignerConfiguration{KeyID: string(identifier)}
				}
				intermediate.AddSubordinate(identifier, subordinate)
			}
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

			for range 50 {
				signers, err := cfg.GetSubordinateJWKs(context.Background())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := make([]string, 0, len(signers))
				for _, signer := range signers {
					got = append(got, signer.KeyID)
				}
				if len(got) != len(tc.expected) {
					t.Fatalf("expected signers %v, got %v", tc.expected, got)
				}
				for i := range got {
					if got[i] != tc.expected[i] {
						t.Fatalf("which subordinate keeps a shared key ID must not change between requests, so signers come in subject order: expected %v, got %v", tc.expected, got)
					}
				}
			}
		})
	}
}

func TestServerConfiguration_GetSubordinate_ACacheTimeUnderOneSecondKeepsNothing(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	for _, tc := range []struct {
		cacheTime time.Duration
		kept      bool
	}{
		{cacheTime: 0},
		{cacheTime: 500 * time.Millisecond},
		{cacheTime: time.Second - time.Nanosecond},
		{cacheTime: time.Second, kept: true},
	} {
		t.Run(tc.cacheTime.String(), func(t *testing.T) {
			retriever := &cacheRetriever{subordinate: &SubordinateConfiguration{}}
			intermediate := &IntermediateConfiguration{SubordinateCacheTime: tc.cacheTime}
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate, MetadataRetriever: retriever}

			if _, err := cfg.GetSubordinate(context.Background(), identifier); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			intermediate.mu.RLock()
			_, kept := intermediate.subordinates[identifier]
			intermediate.mu.RUnlock()
			if kept != tc.kept {
				t.Errorf("CachedAt is recorded in whole seconds, so an entry is kept only for a cache time of at least one second: expected kept to be %t, got %t", tc.kept, kept)
			}
		})
	}
}
