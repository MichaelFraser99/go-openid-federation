package entity_configuration

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_SubordinateSignerSharingSigningKid(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)
	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	}
	override, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.IntermediateConfiguration.AddSubordinate("https://leaf.example.com", &model.SubordinateConfiguration{
		SignerConfiguration: &model.SignerConfiguration{Signer: override, KeyID: cfg.SignerConfiguration.KeyID, Algorithm: "ES256"},
	})
	if _, err := New(t.Context(), cfg); err == nil {
		t.Fatal("expected an override signer reusing the signing kid with different key material to be rejected")
	}
}

func TestNew_SigningKeyEncodedNonMinimally(t *testing.T) {
	signerConfiguration, publicJWK := issuanceSigner(t)
	nonMinimal := map[string]any{}
	for k, v := range publicJWK {
		nonMinimal[k] = v
	}
	for _, claim := range []string{"x", "y"} {
		raw, err := base64.RawURLEncoding.DecodeString(nonMinimal[claim].(string))
		if err != nil {
			t.Fatalf("failed to decode %q: %v", claim, err)
		}
		nonMinimal[claim] = base64.RawURLEncoding.EncodeToString(append([]byte{0x00}, raw...))
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         signerConfiguration,
		EntityConfigurationLifetime: time.Hour,
		EntityConfiguration: model.EntityStatement{
			JWKs: josemodel.Jwks{Keys: []map[string]any{nonMinimal}},
		},
	}

	if _, err := New(t.Context(), cfg); err != nil {
		t.Fatalf("expected a non-minimally encoded copy of the signing key to be accepted, got %v", err)
	}
}

func TestNew_LeafWithoutFederationMetadataPublishesNone(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)

	tests := []struct {
		name      string
		metadata  *model.Metadata
		expectKey bool
	}{
		{
			name:      "a leaf with no metadata publishes no metadata claim",
			metadata:  nil,
			expectKey: false,
		},
		{
			name: "a leaf with only provider metadata gains no federation_entity",
			metadata: &model.Metadata{
				OpenIDConnectOpenIDProviderMetadata: &model.OpenIDConnectOpenIDProviderMetadata{"issuer": "https://leaf.example.com"},
			},
			expectKey: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://leaf.example.com",
				SignerConfiguration:         signerConfiguration,
				EntityConfigurationLifetime: time.Hour,
				EntityConfiguration:         model.EntityStatement{Metadata: tc.metadata},
			}

			token, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			claims := issuedClaims(t, *token)

			metadata, present := claims["metadata"]
			if tc.metadata == nil {
				if present {
					t.Fatalf("expected no metadata claim, got %v", metadata)
				}
				return
			}
			asMap, ok := metadata.(map[string]any)
			if !ok {
				t.Fatalf("expected a metadata object, got %v", metadata)
			}
			if _, gained := asMap["federation_entity"]; gained != tc.expectKey {
				t.Errorf("expected federation_entity present=%t, got %v", tc.expectKey, asMap)
			}
		})
	}
}
