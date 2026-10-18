package entity_configuration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func headerJwkKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func headerJwkPublicJwk(t *testing.T, pub crypto.PublicKey, kid string) map[string]any {
	t.Helper()
	publicJWK, err := jwk.PublicJwk(pub)
	if err != nil {
		t.Fatalf("failed to build public jwk: %v", err)
	}
	(*publicJWK)["kid"] = kid
	(*publicJWK)["alg"] = "RS256"
	return *publicJWK
}

func TestValidate_RejectsEntityConfigurationNotSignedByAPublishedKey(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	realKey := headerJwkKey(t)
	attackerKey := headerJwkKey(t)

	realJwk := headerJwkPublicJwk(t, realKey.Public(), "leaf")
	attackerJwk := headerJwkPublicJwk(t, attackerKey.Public(), "leaf")

	emptyKidJwk := headerJwkPublicJwk(t, realKey.Public(), "")

	tests := []struct {
		name          string
		head          map[string]any
		signer        crypto.Signer
		publishedKeys []any
		expectErr     bool
	}{
		{
			name:      "configuration signed by its own published key is accepted",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256"},
			signer:    realKey,
			expectErr: false,
		},
		{
			name:      "attacker key carried in the jwk header is not trusted",
			head:      map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "RS256", "jwk": attackerJwk},
			signer:    attackerKey,
			expectErr: true,
		},
		{
			name:          "empty kid matching an empty published kid is rejected",
			head:          map[string]any{"kid": "", "typ": "entity-statement+jwt", "alg": "RS256"},
			signer:        realKey,
			publishedKeys: []any{emptyKidJwk},
			expectErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			publishedKeys := tc.publishedKeys
			if publishedKeys == nil {
				publishedKeys = []any{realJwk}
			}
			body := map[string]any{
				"iss":      string(leaf),
				"sub":      string(leaf),
				"iat":      time.Now().UTC().Unix(),
				"exp":      time.Now().Add(time.Hour).UTC().Unix(),
				"jwks":     map[string]any{"keys": publishedKeys},
				"metadata": map[string]any{},
			}

			token, err := jwt.New(tc.signer, tc.head, body, jwt.Opts{Algorithm: josemodel.RS256})
			if err != nil {
				t.Fatalf("failed to sign entity configuration: %v", err)
			}

			result, err := Validate(context.Background(), model.Configuration{}, leaf, *token)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected entity configuration to be rejected, got accepted result for sub %q", result.Sub)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected entity configuration to be accepted, got error: %v", err)
			}
			if result.Sub != leaf {
				t.Fatalf("expected sub %q, got %q", leaf, result.Sub)
			}
		})
	}
}
