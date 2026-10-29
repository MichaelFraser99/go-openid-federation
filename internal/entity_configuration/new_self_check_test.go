package entity_configuration

import (
	"errors"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type strictRelyingPartyType struct{}

func (strictRelyingPartyType) Identifier() string { return "openid_relying_party" }

func (strictRelyingPartyType) VerifyMetadata(metadata map[string]any) error {
	if _, present := metadata["organization_name"]; !present {
		return errors.New("this deployment requires 'organization_name'")
	}
	return nil
}

func (strictRelyingPartyType) VerifyMetadataPolicy(map[string]model.PolicyOperators) error {
	return nil
}

func (strictRelyingPartyType) VerifyResolvedMetadata(map[string]any) error { return nil }

func TestNew_RefusesConfigurationsItsOwnParserRejects(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)

	tests := []struct {
		name      string
		step      string
		configure func(cfg *model.ServerConfiguration)
		expectErr string
	}{
		{
			name: "a trust mark owner with no key set",
			step: "3.2 step 22",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{
					"https://tm.example.com/a": {Sub: "https://owner.example.com"},
				}
			},
			expectErr: "refusing to publish",
		},
		{
			name: "a trust mark owner with an empty key set",
			step: "3.1.1",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{
					"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{}}},
				}
			},
			expectErr: "the trust_mark_owners entry for \"https://tm.example.com/a\" holds no usable key",
		},
		{
			name: "a trust mark owner whose every key is unreadable",
			step: "3.1.1",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{
					"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "k"}}}},
				}
			},
			expectErr: "holds no usable key",
		},
		{
			name: "federation_entity carrying its own key set",
			step: "section 5.1.1",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.Metadata = &model.Metadata{
					FederationMetadata: &model.FederationMetadata{
						"jwks": map[string]any{"keys": []any{}},
					},
				}
			},
			expectErr: "refusing to publish",
		},
		{
			name: "a trust mark owner whose sub is not an entity identifier",
			step: "3.2 step 22",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{
					"https://tm.example.com/a": {
						Sub:  "http://owner.example.com",
						JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "a"}}},
					},
				}
			},
			expectErr: "refusing to publish",
		},
	}

	t.Run("a consumer registered entity type is applied at issuance", func(t *testing.T) {
		cfg := model.ServerConfiguration{
			EntityIdentifier:            "https://leaf.example.com",
			SignerConfiguration:         signerConfiguration,
			EntityConfigurationLifetime: time.Hour,
		}
		cfg.EntityTypes = model.EntityTypeRegistry{
			"openid_relying_party": strictRelyingPartyType{},
		}
		cfg.EntityConfiguration.Metadata = &model.Metadata{
			OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://leaf.example.com/cb"}},
		}

		if _, err := New(t.Context(), cfg); err == nil {
			t.Fatal("expected the consumer registered entity type to refuse issuance")
		} else if !strings.Contains(err.Error(), "refusing to publish") {
			t.Fatalf("expected a refusal to publish, got %v", err)
		}
	})

	t.Run("a negative lifetime is refused", func(t *testing.T) {
		cfg := model.ServerConfiguration{
			EntityIdentifier:            "https://leaf.example.com",
			SignerConfiguration:         signerConfiguration,
			EntityConfigurationLifetime: -time.Hour,
		}
		if _, err := New(t.Context(), cfg); err == nil {
			t.Fatal("expected a negative lifetime to be refused")
		} else if !strings.Contains(err.Error(), "must not be negative") {
			t.Fatalf("expected the negative lifetime to be named, got %v", err)
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://leaf.example.com",
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: time.Hour,
			}
			tc.configure(&cfg)

			token, err := New(t.Context(), cfg)
			if err == nil {
				t.Fatalf("[%s] expected issuance to be refused, got a signed configuration %v", tc.step, token)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
		})
	}
}

func TestNew_PublishesAnOwnerWithOneUsableKeyBesideAnUnreadableOne(t *testing.T) {
	signerConfiguration, publicJWK := issuanceSigner(t)
	owner := map[string]any{}
	for k, v := range publicJWK {
		owner[k] = v
	}
	owner["kid"] = "owner"
	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
		EntityConfiguration: model.EntityStatement{TrustMarkOwners: map[string]model.TrustMarkOwner{
			"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{{"kid": "unreadable"}, owner}}},
		}},
	}
	if _, err := New(t.Context(), cfg); err != nil {
		t.Fatalf("[3.1.1] an owner holding a usable key must be published, whatever else its set holds, got %v", err)
	}
}

func TestNew_IssuedConfigurationSurvivesItsOwnParser(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)

	tests := []struct {
		name     string
		lifetime time.Duration
	}{
		{name: "an explicit lifetime", lifetime: time.Hour},
		{name: "no lifetime falls back to the default", lifetime: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://leaf.example.com",
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: tc.lifetime,
				AuthorityHints:              []model.EntityIdentifier{"https://ta.example.com"},
			}

			token, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("expected the configuration to be issued, got %v", err)
			}

			claims := issuedClaims(t, *token)
			var statement model.EntityStatement
			raw := marshalClaims(t, claims)
			if err := statement.UnmarshalJSON(raw); err != nil {
				t.Fatalf("the issued configuration is rejected by this library's own parser: %v", err)
			}
			if statement.Iat >= statement.Exp {
				t.Errorf("expected a positive lifetime, got iat %d and exp %d", statement.Iat, statement.Exp)
			}
		})
	}
}
