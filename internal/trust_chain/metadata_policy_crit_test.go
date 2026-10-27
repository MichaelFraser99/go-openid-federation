package trust_chain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const (
	criticalOperatorLeaf   = model.EntityIdentifier("https://leaf.example.com")
	criticalOperatorAnchor = model.EntityIdentifier("https://ta.example.com")
)

func criticalOperatorSign(t *testing.T, signer crypto.Signer, body map[string]any) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": "test-key", "typ": "entity-statement+jwt", "alg": "RS256"}, body, jwt.Opts{Algorithm: jwa.RS256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return *token
}

func criticalOperatorJwks(t *testing.T, signer crypto.Signer) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build jwk: %v", err)
	}
	(*publicJWK)["kid"] = "test-key"
	return map[string]any{"keys": []any{*publicJWK}}
}

func TestResolveMetadata_RejectsUnsupportedCriticalPolicyOperator(t *testing.T) {
	tests := map[string]map[string]any{
		"listed and not used": {
			"metadata_policy":      map[string]any{"federation_entity": map[string]any{"contacts": map[string]any{"add": []any{"ops@ta.example.com"}}}},
			"metadata_policy_crit": []any{"regexp"},
		},
		"listed with no metadata_policy": {
			"metadata_policy_crit": []any{"regexp"},
		},
	}

	for name, subordinateExtra := range tests {
		t.Run(name, func(t *testing.T) {
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
				"metadata": map[string]any{"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}}},
			}
			subordinate := map[string]any{
				"iss": string(criticalOperatorAnchor), "sub": string(criticalOperatorLeaf),
				"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
				"jwks": criticalOperatorJwks(t, leafKey),
			}
			for k, v := range subordinateExtra {
				subordinate[k] = v
			}
			anchor := map[string]any{
				"iss": string(criticalOperatorAnchor), "sub": string(criticalOperatorAnchor),
				"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
				"jwks":     criticalOperatorJwks(t, anchorKey),
				"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(criticalOperatorAnchor) + "/fetch"}},
			}

			chain := []string{
				criticalOperatorSign(t, leafKey, leaf),
				criticalOperatorSign(t, anchorKey, subordinate),
				criticalOperatorSign(t, anchorKey, anchor),
			}

			if _, err := ResolveMetadata(t.Context(), model.Configuration{}, criticalOperatorAnchor, criticalOperatorAnchor, chain, nil); err == nil {
				t.Fatal("chain accepted although metadata_policy_crit lists an operator the library does not support")
			} else if !strings.Contains(err.Error(), "none of which this implementation understands") {
				t.Fatalf("expected the rejection to name the unsupported operator, got %v", err)
			}
		})
	}
}
