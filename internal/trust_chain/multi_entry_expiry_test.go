package trust_chain

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_MultiEntryChainIsGatedOnExpiry(t *testing.T) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	anchorKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	leaf := map[string]any{
		"iss": string(criticalOperatorLeaf), "sub": string(criticalOperatorLeaf),
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": criticalOperatorJwks(t, leafKey), "authority_hints": []string{string(criticalOperatorAnchor)},
	}
	subordinate := map[string]any{
		"iss": string(criticalOperatorAnchor), "sub": string(criticalOperatorLeaf),
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": criticalOperatorJwks(t, leafKey),
	}
	anchorBody := map[string]any{
		"iss": string(criticalOperatorAnchor), "sub": string(criticalOperatorAnchor),
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"jwks": criticalOperatorJwks(t, anchorKey),
	}
	signedAnchor := criticalOperatorSign(t, anchorKey, anchorBody)

	raw, err := json.Marshal(criticalOperatorJwks(t, anchorKey))
	if err != nil {
		t.Fatal(err)
	}
	var anchorJwks josemodel.Jwks
	if err := json.Unmarshal(raw, &anchorJwks); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		anchorExp time.Duration
		expectErr string
	}{
		{name: "a live cached anchor configuration resolves", anchorExp: time.Hour},
		{name: "a cached anchor configuration that expired is refused", anchorExp: -2 * time.Hour, expectErr: "expired"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cached := &model.EntityStatement{
				Iss: criticalOperatorAnchor, Sub: criticalOperatorAnchor,
				Iat:  now.Add(-3 * time.Hour).Unix(),
				Exp:  now.Add(tc.anchorExp).Unix(),
				JWKs: anchorJwks,
			}
			cache := resolvecache.New()
			cache.Store(criticalOperatorAnchor, &signedAnchor, cached)

			chain := []string{
				criticalOperatorSign(t, leafKey, leaf),
				criticalOperatorSign(t, anchorKey, subordinate),
			}

			result, err := ResolveMetadata(t.Context(), model.Configuration{}, criticalOperatorAnchor, chain, cache)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected the chain to resolve, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a chain whose cached anchor configuration expired was resolved, exp %d", result.Exp)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected an expiry error, got %v", err)
			}
		})
	}
}
