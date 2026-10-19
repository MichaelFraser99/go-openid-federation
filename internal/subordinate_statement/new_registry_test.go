package subordinate_statement

import (
	"errors"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type policyRejectingType struct{}

func (policyRejectingType) Identifier() string { return "openid_relying_party" }

func (policyRejectingType) VerifyMetadata(map[string]any) error { return nil }

func (policyRejectingType) VerifyMetadataPolicy(map[string]model.PolicyOperators) error {
	return errors.New("this deployment forbids a policy on openid_relying_party")
}

func (policyRejectingType) VerifyResolvedMetadata(map[string]any) error { return nil }

func TestNew_AppliesTheRegistryToAnIssuedPolicy(t *testing.T) {
	policy := model.MetadataPolicy{}
	if err := policy.UnmarshalJSON([]byte(`{"openid_relying_party":{"scope":{"value":"openid"}}}`)); err != nil {
		t.Fatalf("failed to build the policy fixture: %v", err)
	}

	retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		signer := testKey(t)
		return &model.SubordinateConfiguration{
			JWKs:     josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, signer.Public(), "leaf")}},
			Policies: policy,
		}, &model.SignerConfiguration{
			Signer:    signer,
			KeyID:     "ta",
			Algorithm: "RS256",
		}, nil
	}

	tests := []struct {
		name      string
		registry  model.EntityTypeRegistry
		expectErr string
	}{
		{name: "with no registry the policy is issued", registry: nil},
		{
			name:      "a registered type that forbids the policy refuses issuance",
			registry:  model.EntityTypeRegistry{"openid_relying_party": policyRejectingType{}},
			expectErr: "refusing to publish",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				EntityIdentifier: "https://ta.example.com",
				IntermediateConfiguration: &model.IntermediateConfiguration{
					SubordinateStatementLifetime: time.Hour,
				},
			}
			cfg.EntityTypes = tc.registry

			token, err := New(t.Context(), "https://leaf.example.com", retriever, cfg)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected the statement to be issued, got %v", err)
				}
				if token == nil {
					t.Fatal("expected a signed statement")
				}
				return
			}
			if err == nil {
				t.Fatal("expected the registered type to refuse issuance")
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected a refusal to publish, got %v", err)
			}
		})
	}
}
