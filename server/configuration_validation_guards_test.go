package server

import (
	"errors"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func expectConfigurationFault(t *testing.T, cfg model.ServerConfiguration, reference, says string) {
	t.Helper()
	err := validateConfiguration(cfg)
	if err == nil || !strings.Contains(err.Error(), says) {
		t.Fatalf("[%s] expected the configuration to be refused naming %q, got %v", reference, says, err)
	}
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Errorf("[%s] the refusal carries the private value: %v", reference, err)
	}
}

func TestValidateConfiguration_RefusesASignerAlgorithmItsKeyCannotSignWith(t *testing.T) {
	cfg := validServerConfiguration(t)
	if err := validateConfiguration(cfg); err != nil {
		t.Fatalf("the fixture is wrong: %v", err)
	}
	cfg.SignerConfiguration.Algorithm = "PS384"
	expectConfigurationFault(t, cfg, "RFC 7518 3.5", "SignerConfiguration.Signer holds a key that cannot sign with SignerConfiguration.Algorithm PS384")
}

func TestValidateConfiguration_RefusesAnAuthorityHintNamingThisEntity(t *testing.T) {
	for _, hint := range []model.EntityIdentifier{"https://entity.example.com", "https://entity.example.com/"} {
		t.Run(string(hint), func(t *testing.T) {
			cfg := validServerConfiguration(t)
			cfg.AuthorityHints = []model.EntityIdentifier{"https://ta.example.com", hint}
			expectConfigurationFault(t, cfg, "3.1.1", "AuthorityHints[1] names this server's own EntityIdentifier")
		})
	}
}

func TestValidateConfiguration_RefusesEachPublishedKeySetHoldingAPrivateKey(t *testing.T) {
	leaked := map[string]any{"kty": "oct", "kid": "leaked", "k": "SECRETVALUE"}
	tests := map[string]struct {
		change func(cfg *model.ServerConfiguration)
		path   string
	}{
		"the jwks claim": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.JWKs = josemodel.Jwks{Keys: []map[string]any{leaked}}
		}, path: `"jwks" key set`},
		"a metadata jwks": {change: func(cfg *model.ServerConfiguration) {
			cfg.EntityConfiguration.Metadata = &model.Metadata{Extensions: map[string]map[string]any{"x_custom": {"jwks": map[string]any{"keys": []any{leaked}}}}}
		}, path: `"metadata.x_custom.jwks" key set`},
		"a trust_mark_owners jwks": {change: func(cfg *model.ServerConfiguration) {
			owner := map[string]any{"kty": "EC", "crv": "P-256", "kid": "owner", "x": "x", "y": "y"}
			cfg.EntityConfiguration.TrustMarkOwners = map[string]model.TrustMarkOwner{"https://tm.example.com/a": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{owner, leaked}}}}
		}, path: `"trust_mark_owners.https://tm.example.com/a.jwks" key set`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validServerConfiguration(t)
			tc.change(&cfg)
			expectConfigurationFault(t, cfg, "RFC 7518 6.4.1", "EntityConfiguration would publish private key material: the "+tc.path)
		})
	}
}

type stringNameEntityType struct{}

func (stringNameEntityType) Identifier() string { return "x_named" }

func (stringNameEntityType) VerifyMetadata(metadata map[string]any) error {
	if _, ok := metadata["name"].(string); !ok {
		return errors.New("name must be a string")
	}
	return nil
}

func (stringNameEntityType) VerifyMetadataPolicy(map[string]model.PolicyOperators) error { return nil }

func (stringNameEntityType) VerifyResolvedMetadata(map[string]any) error { return nil }

func TestValidateConfiguration_JudgesMetadataAsItIsPublished(t *testing.T) {
	t.Run("a registered entity type whose own check refuses the published metadata", func(t *testing.T) {
		cfg := validServerConfiguration(t)
		cfg.EntityTypes = model.EntityTypeRegistry{"x_named": stringNameEntityType{}}
		cfg.EntityConfiguration.Metadata = &model.Metadata{Extensions: map[string]map[string]any{"x_named": {"name": 7}}}
		expectConfigurationFault(t, cfg, "5", "EntityConfiguration.Metadata is not valid: invalid x_named metadata: name must be a string")
	})
	t.Run("a registered entity type whose own check accepts the typed value as it is published", func(t *testing.T) {
		cfg := validServerConfiguration(t)
		cfg.EntityTypes = model.EntityTypeRegistry{"x_named": stringNameEntityType{}}
		cfg.EntityConfiguration.Metadata = &model.Metadata{Extensions: map[string]map[string]any{"x_named": {"name": model.EntityIdentifier("https://entity.example.com")}}}
		if err := validateConfiguration(cfg); err != nil {
			t.Fatalf("[5] expected the check to see the value as published, a string, got %v", err)
		}
	})
	t.Run("a typed value that publishes as an insecure URL", func(t *testing.T) {
		cfg := validServerConfiguration(t)
		cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"jwks_uri": model.EntityIdentifier("http://insecure.example.com")}}
		expectConfigurationFault(t, cfg, "5.2.1", "EntityConfiguration.Metadata is not valid")
	})
	t.Run("a value that cannot be written as JSON", func(t *testing.T) {
		cfg := validServerConfiguration(t)
		cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"client_name": make(chan int)}}
		expectConfigurationFault(t, cfg, "5", "EntityConfiguration.Metadata cannot be written")
	})
	t.Run("a typed value that publishes as a well-formed parameter", func(t *testing.T) {
		cfg := validServerConfiguration(t)
		cfg.EntityConfiguration.Metadata = &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"jwks_uri": model.EntityIdentifier("https://entity.example.com/jwks")}}
		if err := validateConfiguration(cfg); err != nil {
			t.Fatalf("[5.2.1] expected metadata that publishes well-formed to be accepted, got %v", err)
		}
	})
}
