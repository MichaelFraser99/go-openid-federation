package entity_configuration

import (
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_RefusesConfigurationsItsOwnParserRejects(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)

	tests := []struct {
		name      string
		step      string
		configure func(cfg *model.ServerConfiguration)
		expectErr string
	}{
		{
			name: "a crit claim cannot be carried",
			step: "3.2 step 13",
			configure: func(cfg *model.ServerConfiguration) {
				cfg.EntityConfiguration.Crit = []string{"x-custom"}
			},
			expectErr: "cannot issue an entity configuration carrying a 'crit' claim",
		},
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
