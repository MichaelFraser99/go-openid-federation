package trust_chain

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_SingleStatementChainIsGatedOnExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expIn     time.Duration
		expectErr string
	}{
		{name: "a live anchor configuration resolves", expIn: time.Hour},
		{
			name:      "expired inside the clock skew leeway cannot produce a response",
			expIn:     -30 * time.Second,
			expectErr: "not in the future",
		},
		{
			name:      "expired beyond the clock skew leeway is refused on parse",
			expIn:     -5 * time.Minute,
			expectErr: "entity statement has expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()

			anchor := map[string]any{
				"iss":      string(criticalOperatorAnchor),
				"sub":      string(criticalOperatorAnchor),
				"iat":      now.Add(-time.Hour).Unix(),
				"exp":      now.Add(tc.expIn).Unix(),
				"jwks":     criticalOperatorJwks(t, key),
				"metadata": map[string]any{"federation_entity": map[string]any{"organization_name": "Anchor"}},
			}

			chain := []string{criticalOperatorSign(t, key, anchor)}

			result, err := ResolveMetadata(t.Context(), model.Configuration{}, criticalOperatorAnchor, chain, nil)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("expected a chain expired by %s to be refused, got exp %d", -tc.expIn, result.Exp)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the single statement chain to resolve, got %v", err)
			}
			if result.Exp != anchor["exp"].(int64) {
				t.Errorf("expected the response exp to be the statement exp %d, got %d", anchor["exp"], result.Exp)
			}
		})
	}
}
