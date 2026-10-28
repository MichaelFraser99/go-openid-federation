package model

import (
	"strings"
	"testing"
)

func TestVerifyResolved_AppliesTheRulesTheParserApplies(t *testing.T) {
	subject := EntityIdentifier("https://leaf.example.com")

	tests := map[string]struct {
		reference string
		metadata  *Metadata
		refused   bool
	}{
		"an rp token_endpoint_auth_signing_alg of none": {
			reference: "OIDC Registration 2",
			metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
				"redirect_uris":                   []any{"https://leaf.example.com/cb"},
				"token_endpoint_auth_signing_alg": "none",
			}},
			refused: true,
		},
		"an rp carrying both jwks and jwks_uri": {
			reference: "OpenID Federation 5.2.1",
			metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://leaf.example.com/cb"},
				"jwks":          map[string]any{"keys": []any{}},
				"jwks_uri":      "https://leaf.example.com/jwks",
			}},
			refused: true,
		},
		"an as token_endpoint_auth_signing_alg_values_supported holding none": {
			reference: "OIDC Registration 2",
			metadata: &Metadata{OAuthAuthorizationServerMetadata: &OAuthAuthorizationServerMetadata{
				"issuer":                   string(subject),
				"response_types_supported": []any{"code"},
				"token_endpoint_auth_signing_alg_values_supported": []any{"none"},
			}},
			refused: true,
		},
		"a federation_entity endpoint that is not https": {
			reference: "OpenID Federation 5.2.1",
			metadata: &Metadata{FederationMetadata: &FederationMetadata{
				"federation_fetch_endpoint": "http://leaf.example.com/fetch",
			}},
			refused: true,
		},
		"an rp whose metadata is conformant": {
			reference: "OpenID Federation 6.1",
			metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
				"redirect_uris":                   []any{"https://leaf.example.com/cb"},
				"token_endpoint_auth_signing_alg": "RS256",
			}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.metadata.VerifyResolved(nil, subject)
			if test.refused {
				if err == nil {
					t.Fatalf("[%s] a metadata policy must not be able to reinstate a value the parser refuses, but %s resolved cleanly", test.reference, name)
				}
				return
			}
			if err != nil {
				t.Errorf("[%s] conformant resolved metadata must pass, got %v", test.reference, err)
			}
		})
	}
}

func TestVerifyResolved_RequiresTheIssuerToBeTheEntityIdentifier(t *testing.T) {
	subject := EntityIdentifier("https://op.example.com")

	tests := map[string]struct {
		reference string
		metadata  *Metadata
		refused   bool
		says      string
	}{
		"an openid_provider issuer naming another entity": {
			reference: "Connect 1.1 5.1.2",
			metadata: &Metadata{OpenIDConnectOpenIDProviderMetadata: &OpenIDConnectOpenIDProviderMetadata{
				"issuer": "https://attacker.example.com",
			}},
			refused: true,
			says:    "'issuer' must be the entity identifier",
		},
		"an openid_provider issuer with a path appended": {
			reference: "Connect 1.1 5.1.2",
			metadata: &Metadata{OpenIDConnectOpenIDProviderMetadata: &OpenIDConnectOpenIDProviderMetadata{
				"issuer": "https://op.example.com/openid",
			}},
			refused: true,
			says:    "'issuer' must be the entity identifier",
		},
		"an oauth_authorization_server issuer naming another entity": {
			reference: "Connect 1.1 5.1.3",
			metadata: &Metadata{OAuthAuthorizationServerMetadata: &OAuthAuthorizationServerMetadata{
				"issuer": "https://attacker.example.com",
			}},
			refused: true,
			says:    "'issuer' must be the entity identifier",
		},
		"an issuer that is not a string": {
			reference: "Connect 1.1 5.1.2",
			metadata: &Metadata{OpenIDConnectOpenIDProviderMetadata: &OpenIDConnectOpenIDProviderMetadata{
				"issuer": map[string]any{"not": "a string"},
			}},
			refused: true,
			says:    "'issuer' must be a string",
		},
		"an openid_provider issuer equal to the identifier": {
			reference: "Connect 1.1 5.1.2",
			metadata: &Metadata{OpenIDConnectOpenIDProviderMetadata: &OpenIDConnectOpenIDProviderMetadata{
				"issuer":                                "https://op.example.com",
				"authorization_endpoint":                "https://op.example.com/authorize",
				"response_types_supported":              []any{"code"},
				"subject_types_supported":               []any{"public"},
				"id_token_signing_alg_values_supported": []any{"RS256"},
				"jwks_uri":                              "https://op.example.com/jwks",
				"token_endpoint":                        "https://op.example.com/token",
			}},
		},
		"an entity type with no issuer rule": {
			reference: "Connect 1.1 5.1.2",
			metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://op.example.com/cb"},
			}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.metadata.VerifyResolved(nil, subject)
			if test.refused {
				if err == nil {
					t.Fatalf("[%s] the issuer parameter MUST match the Federation Entity Identifier, but %s resolved cleanly", test.reference, name)
				}
				if !strings.Contains(err.Error(), test.says) {
					t.Errorf("[%s] the refusal must say %q, got %v", test.reference, test.says, err)
				}
				return
			}
			if err != nil {
				t.Errorf("[%s] expected this to resolve cleanly, got %v", test.reference, err)
			}
		})
	}
}
