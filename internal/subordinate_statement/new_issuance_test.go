package subordinate_statement

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func issuanceSigner(t *testing.T) (model.SignerConfiguration, map[string]any) {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to create public jwk: %v", err)
	}
	(*publicJWK)["alg"] = "ES256"
	return model.SignerConfiguration{
		KeyID:     (*publicJWK)["kid"].(string),
		Algorithm: "ES256",
		Signer:    signer,
	}, *publicJWK
}

func issuedClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS with three parts, got %d", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode issued claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("failed to unmarshal issued claims: %v", err)
	}
	return claims
}

func TestNew_IssuesConformingSubordinateStatements(t *testing.T) {
	const (
		issuer  = model.EntityIdentifier("https://ta.example.com")
		subject = model.EntityIdentifier("https://leaf.example.com")
	)

	tests := []struct {
		name      string
		policies  func(t *testing.T) model.MetadataPolicy
		keys      func(t *testing.T) []map[string]any
		expectErr bool
		validate  func(t *testing.T, claims map[string]any)
	}{
		{
			name: "no configured policy omits the metadata_policy claim",
			validate: func(t *testing.T, claims map[string]any) {
				if policy, present := claims["metadata_policy"]; present {
					t.Errorf("expected metadata_policy to be omitted, got %v", policy)
				}
			},
		},
		{
			name: "a configured policy is published",
			policies: func(t *testing.T) model.MetadataPolicy {
				t.Helper()
				var policy model.MetadataPolicy
				if err := json.Unmarshal([]byte(`{"federation_entity":{"contacts":{"add":["ops@ta.example.com"]}}}`), &policy); err != nil {
					t.Fatalf("failed to build policy: %v", err)
				}
				return policy
			},
			validate: func(t *testing.T, claims map[string]any) {
				policy, ok := claims["metadata_policy"].(map[string]any)
				if !ok {
					t.Fatalf("expected metadata_policy to be published, got %v", claims["metadata_policy"])
				}
				if _, ok := policy["federation_entity"]; !ok {
					t.Errorf("expected the federation_entity policy to be published, got %v", policy)
				}
			},
		},
		{
			name: "duplicate subject kid values are rejected",
			keys: func(t *testing.T) []map[string]any {
				t.Helper()
				_, first := issuanceSigner(t)
				_, second := issuanceSigner(t)
				first["kid"] = "dup"
				second["kid"] = "dup"
				return []map[string]any{first, second}
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signerConfiguration, _ := issuanceSigner(t)
			_, subjectJWK := issuanceSigner(t)

			keys := []map[string]any{subjectJWK}
			if tc.keys != nil {
				keys = tc.keys(t)
			}

			subordinateConfiguration := &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: keys},
			}
			if tc.policies != nil {
				subordinateConfiguration.Policies = tc.policies(t)
			}

			cfg := model.ServerConfiguration{
				EntityIdentifier:    issuer,
				SignerConfiguration: signerConfiguration,
				IntermediateConfiguration: &model.IntermediateConfiguration{
					SubordinateStatementLifetime: time.Hour,
				},
			}

			token, err := New(context.Background(), subject, func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return subordinateConfiguration, &signerConfiguration, nil
			}, cfg)

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected an error, got a signed subordinate statement")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			tc.validate(t, issuedClaims(t, *token))
		})
	}
}
