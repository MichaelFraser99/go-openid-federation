package model

import (
	"strings"
	"testing"
)

func TestEntityTypes_KeySetClaimsAreCheckedOnEveryTypeThatMayCarryThem(t *testing.T) {
	cases := []struct {
		name      string
		reference string
		metadata  map[string]any
		expectErr string
	}{
		{
			name:      "a jwks_uri over plain http",
			reference: "5.2.1",
			metadata:  map[string]any{"jwks_uri": "http://keys.example.com/jwks"},
			expectErr: "'jwks_uri' must use the 'https' scheme",
		},
		{
			name:      "a signed_jwks_uri over plain http",
			reference: "5.2.1",
			metadata:  map[string]any{"signed_jwks_uri": "http://keys.example.com/jwks.jose"},
			expectErr: "'signed_jwks_uri' must use the 'https' scheme",
		},
		{
			name:      "a jwks that is not a JSON object",
			reference: "5.2.1",
			metadata:  map[string]any{"jwks": []any{}},
			expectErr: "'jwks' must be a JSON object",
		},
		{
			name:      "a jwks with no keys member is not a JWK Set",
			reference: "5.2.1",
			metadata:  map[string]any{"jwks": map[string]any{}},
			expectErr: "'jwks' is missing the required 'keys' member",
		},
		{
			name:      "a jwks whose key omits kty",
			reference: "RFC 7517 4.1",
			metadata:  map[string]any{"jwks": map[string]any{"keys": []any{map[string]any{"kid": "a"}}}},
			expectErr: "position 0 of 'keys'",
		},
		{
			name:      "a jwks carrying a well formed key",
			reference: "5.2.1",
			metadata:  map[string]any{"jwks": map[string]any{"keys": []any{map[string]any{"kid": "a", "kty": "RSA", "n": "AQAB", "e": "AQAB"}}}},
		},
		{
			name:      "a jwks_uri over https",
			reference: "5.2.1",
			metadata:  map[string]any{"jwks_uri": "https://keys.example.com/jwks"},
		},
		{
			name:      "a signed_jwks_uri over https",
			reference: "5.2.1",
			metadata:  map[string]any{"signed_jwks_uri": "https://keys.example.com/jwks.jose"},
		},
	}

	registry := DefaultEntityTypeRegistry()

	for _, entityType := range builtInEntityTypes {
		if entityType == "federation_entity" {
			continue
		}
		for _, tc := range cases {
			t.Run(entityType+": "+tc.name, func(t *testing.T) {
				definition, known := registry[entityType]
				if !known {
					t.Fatalf("%s is not in the default registry", entityType)
				}

				metadata := map[string]any{"placeholder": "so the type is not empty"}
				for claim, value := range tc.metadata {
					metadata[claim] = value
				}

				err := definition.VerifyMetadata(metadata)
				if tc.expectErr == "" {
					if err != nil && strings.Contains(err.Error(), "jwks") {
						t.Fatalf("[%s] expected the key claim to be accepted, got %v", tc.reference, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("[%s] expected %s to refuse the claim", tc.reference, entityType)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
				}
			})
		}
	}
}

func TestFederationEntity_RefusesKeySetClaimsEntirely(t *testing.T) {
	for _, claim := range []string{"jwks", "jwks_uri", "signed_jwks_uri"} {
		t.Run(claim, func(t *testing.T) {
			err := FederationMetadata(map[string]any{claim: "https://keys.example.com/jwks"}).VerifyMetadata()
			if err == nil {
				t.Fatal("[5.2.1] these parameters must not be used in federation_entity metadata")
			}
			if !strings.Contains(err.Error(), "must not be used in federation_entity metadata") {
				t.Fatalf("[5.2.1] expected the refusal to name the rule, got %v", err)
			}
		})
	}
}
