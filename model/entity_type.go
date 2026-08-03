package model

import "fmt"

// EntityType describes a single Entity Type Identifier and the validation applied to metadata,
// metadata policy, and resolved metadata carrying that identifier.
type EntityType interface {
	Identifier() string
	VerifyMetadata(metadata map[string]any) error
	VerifyMetadataPolicy(policy map[string]PolicyOperators) error
	VerifyResolvedMetadata(metadata map[string]any) error
}

// EntityTypeRegistry maps Entity Type Identifiers to their definitions. Entries supplied by a
// consumer are merged over the built-in definitions, so a registration under a built-in identifier
// replaces it.
type EntityTypeRegistry map[string]EntityType

type builtInEntityType struct {
	identifier string
	verify     func(map[string]any) error
}

func (b builtInEntityType) Identifier() string {
	return b.identifier
}

func (b builtInEntityType) VerifyMetadata(metadata map[string]any) error {
	if b.verify == nil {
		return nil
	}
	return b.verify(metadata)
}

func (b builtInEntityType) VerifyMetadataPolicy(map[string]PolicyOperators) error {
	return nil
}

func (b builtInEntityType) VerifyResolvedMetadata(map[string]any) error {
	return nil
}

var builtInEntityTypeDefinitions = map[string]EntityType{
	"federation_entity": builtInEntityType{
		identifier: "federation_entity",
		verify:     func(m map[string]any) error { return FederationMetadata(m).VerifyMetadata() },
	},
	"openid_relying_party": builtInEntityType{
		identifier: "openid_relying_party",
		verify:     func(m map[string]any) error { return OpenIDRelyingPartyMetadata(m).VerifyMetadata() },
	},
	"openid_provider": builtInEntityType{
		identifier: "openid_provider",
		verify:     func(m map[string]any) error { return OpenIDConnectOpenIDProviderMetadata(m).VerifyMetadata() },
	},
	"oauth_authorization_server": builtInEntityType{
		identifier: "oauth_authorization_server",
		verify:     func(m map[string]any) error { return OAuthAuthorizationServerMetadata(m).VerifyMetadata() },
	},
	"oauth_client": builtInEntityType{
		identifier: "oauth_client",
		verify:     func(m map[string]any) error { return OAuthClientMetadata(m).VerifyMetadata() },
	},
	"oauth_resource": builtInEntityType{
		identifier: "oauth_resource",
		verify:     func(m map[string]any) error { return OAuthResourceMetadata(m).VerifyMetadata() },
	},
	"openid_wallet_provider": builtInEntityType{
		identifier: "openid_wallet_provider",
		verify:     func(m map[string]any) error { return OpenIDWalletProviderMetadata(m).VerifyMetadata() },
	},
	"openid_credential_issuer": builtInEntityType{
		identifier: "openid_credential_issuer",
		verify:     func(m map[string]any) error { return OpenIDCredentialIssuerMetadata(m).VerifyMetadata() },
	},
	"openid_credential_verifier": builtInEntityType{
		identifier: "openid_credential_verifier",
		verify:     func(m map[string]any) error { return OpenIDCredentialVerifierMetadata(m).VerifyMetadata() },
	},
}

// DefaultEntityTypeRegistry returns the Entity Types defined by the OpenID Federation
// specification family and supported natively by this library.
func DefaultEntityTypeRegistry() EntityTypeRegistry {
	registry := make(EntityTypeRegistry, len(builtInEntityTypeDefinitions))
	for identifier, definition := range builtInEntityTypeDefinitions {
		registry[identifier] = definition
	}
	return registry
}

func (r EntityTypeRegistry) withDefaults() EntityTypeRegistry {
	merged := DefaultEntityTypeRegistry()
	for identifier, definition := range r {
		merged[identifier] = definition
	}
	return merged
}

// Verify runs the registered validation for every Entity Type present in the metadata. Entity
// Types absent from the registry are left untouched, or removed when discardUnrecognised is set.
func (m *Metadata) Verify(registry EntityTypeRegistry, discardUnrecognised bool) error {
	merged := registry.withDefaults()
	for entityType, entityMetadata := range m.byEntityType() {
		definition, recognised := merged[entityType]
		if !recognised {
			if discardUnrecognised {
				delete(m.Extensions, entityType)
			}
			continue
		}
		if err := definition.VerifyMetadata(entityMetadata); err != nil {
			return fmt.Errorf("invalid %s metadata: %w", entityType, err)
		}
	}
	return nil
}

// VerifyResolved runs the registered post-resolution validation for every Entity Type present in
// the metadata, after any metadata policy has been applied.
func (m *Metadata) VerifyResolved(registry EntityTypeRegistry) error {
	merged := registry.withDefaults()
	for entityType, entityMetadata := range m.byEntityType() {
		definition, recognised := merged[entityType]
		if !recognised {
			continue
		}
		if err := definition.VerifyResolvedMetadata(entityMetadata); err != nil {
			return fmt.Errorf("invalid resolved %s metadata: %w", entityType, err)
		}
	}
	return nil
}

// Verify runs the registered policy validation for every Entity Type present in the metadata
// policy. Entity Types absent from the registry are left untouched, or removed when
// discardUnrecognised is set.
func (m *MetadataPolicy) Verify(registry EntityTypeRegistry, discardUnrecognised bool) error {
	merged := registry.withDefaults()
	for entityType, operators := range m.byEntityType() {
		if operators == nil {
			continue
		}
		definition, recognised := merged[entityType]
		if !recognised {
			if discardUnrecognised {
				delete(m.Extensions, entityType)
			}
			continue
		}
		if err := definition.VerifyMetadataPolicy(operators); err != nil {
			return fmt.Errorf("invalid %s metadata policy: %w", entityType, err)
		}
	}
	return nil
}
