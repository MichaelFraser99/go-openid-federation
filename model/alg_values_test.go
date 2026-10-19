package model

import (
	"strings"
	"testing"
)

func providerBase(extra map[string]any) OpenIDConnectOpenIDProviderMetadata {
	m := OpenIDConnectOpenIDProviderMetadata{
		"issuer":                                "https://op.example.com",
		"authorization_endpoint":                "https://op.example.com/authorize",
		"jwks_uri":                              "https://op.example.com/jwks",
		"response_types_supported":              []any{"id_token"},
		"subject_types_supported":               []any{"public"},
		"id_token_signing_alg_values_supported": []any{"ES256"},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func authorizationServerBase(extra map[string]any) OAuthAuthorizationServerMetadata {
	m := OAuthAuthorizationServerMetadata{
		"issuer":                   "https://as.example.com",
		"response_types_supported": []any{"code"},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func relyingPartyBase(extra map[string]any) OpenIDRelyingPartyMetadata {
	m := OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://rp.example.com/cb"}}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func oauthClientBase(extra map[string]any) OAuthClientMetadata {
	m := OAuthClientMetadata{}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestSigningAlgorithmClaims_NonePerParameter(t *testing.T) {
	tests := []struct {
		entityType  string
		key         string
		reference   string
		noneAllowed bool
		build       func(value any) EntityTypeIdentifier
	}{
		{
			entityType: "openid_provider", key: "id_token_signing_alg_values_supported",
			reference: `OIDC Discovery 3: "The value none MAY be supported"`, noneAllowed: true,
			build: func(v any) EntityTypeIdentifier {
				return providerBase(map[string]any{"id_token_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "openid_provider", key: "request_object_signing_alg_values_supported",
			reference: `OIDC Discovery 3: "Servers SHOULD support none and RS256"`, noneAllowed: true,
			build: func(v any) EntityTypeIdentifier {
				return providerBase(map[string]any{"request_object_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "openid_provider", key: "userinfo_signing_alg_values_supported",
			reference: `OIDC Discovery 3: "The value none MAY be included"`, noneAllowed: true,
			build: func(v any) EntityTypeIdentifier {
				return providerBase(map[string]any{"userinfo_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "openid_provider", key: "token_endpoint_auth_signing_alg_values_supported",
			reference: `OIDC Discovery 3: "The value none MUST NOT be used"`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return providerBase(map[string]any{"token_endpoint_auth_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "oauth_authorization_server", key: "token_endpoint_auth_signing_alg_values_supported",
			reference: `RFC 8414 2: "The value none MUST NOT be used"`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return authorizationServerBase(map[string]any{"token_endpoint_auth_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "oauth_authorization_server", key: "revocation_endpoint_auth_signing_alg_values_supported",
			reference: `RFC 8414 2: "The value none MUST NOT be used"`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return authorizationServerBase(map[string]any{"revocation_endpoint_auth_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "oauth_authorization_server", key: "introspection_endpoint_auth_signing_alg_values_supported",
			reference: `RFC 8414 2: "The value none MUST NOT be used"`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return authorizationServerBase(map[string]any{"introspection_endpoint_auth_signing_alg_values_supported": v})
			},
		},
		{
			entityType: "openid_relying_party", key: "token_endpoint_auth_signing_alg",
			reference: `OIDC Registration 2: "The value none MUST NOT be used"`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return relyingPartyBase(map[string]any{"token_endpoint_auth_signing_alg": v})
			},
		},
		{
			entityType: "openid_relying_party", key: "id_token_signed_response_alg",
			reference: `OIDC Registration 2: none permitted for a client using only response types that return no ID Token from the authorization endpoint`, noneAllowed: true,
			build: func(v any) EntityTypeIdentifier {
				return relyingPartyBase(map[string]any{"id_token_signed_response_alg": v})
			},
		},
		{
			entityType: "openid_relying_party", key: "request_object_signing_alg",
			reference: `OIDC Registration 2: "The value none MAY be used"`, noneAllowed: true,
			build: func(v any) EntityTypeIdentifier {
				return relyingPartyBase(map[string]any{"request_object_signing_alg": v})
			},
		},
		{
			entityType: "oauth_client", key: "token_endpoint_auth_signing_alg",
			reference: `OIDC Registration 2: "The value none MUST NOT be used"`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return oauthClientBase(map[string]any{"token_endpoint_auth_signing_alg": v})
			},
		},
		{
			entityType: "oauth_client", key: "request_object_signing_alg",
			reference: `OIDC Registration 2: "The value none MAY be used"`, noneAllowed: true,
			build: func(v any) EntityTypeIdentifier {
				return oauthClientBase(map[string]any{"request_object_signing_alg": v})
			},
		},
		{
			entityType: "federation_entity", key: "endpoint_auth_signing_alg_values_supported",
			reference: `OpenID Federation 1.1 5.1.1`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return FederationMetadata{"endpoint_auth_signing_alg_values_supported": v}
			},
		},
		{
			entityType: "oauth_resource", key: "resource_signing_alg_values_supported",
			reference: `RFC 9728 2`, noneAllowed: false,
			build: func(v any) EntityTypeIdentifier {
				return OAuthResourceMetadata{"resource": "https://rs.example.com", "resource_signing_alg_values_supported": v}
			},
		},
	}

	valueFor := func(key string, alg any) any {
		if strings.HasSuffix(key, "_values_supported") {
			return []any{alg}
		}
		return alg
	}

	for _, tc := range tests {
		t.Run(tc.entityType+"/"+tc.key+"/none", func(t *testing.T) {
			err := tc.build(valueFor(tc.key, "none")).VerifyMetadata()
			if tc.noneAllowed {
				if err != nil {
					t.Fatalf("[%s] expected 'none' to be permitted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected 'none' to be refused, got accepted metadata", tc.reference)
			}
			if !strings.Contains(err.Error(), "'none'") || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("[%s] expected the error to name %q and 'none', got %v", tc.reference, tc.key, err)
			}
		})

		t.Run(tc.entityType+"/"+tc.key+"/a real algorithm", func(t *testing.T) {
			if err := tc.build(valueFor(tc.key, "ES256")).VerifyMetadata(); err != nil {
				t.Fatalf("[%s] expected a real algorithm to be accepted, got %v", tc.reference, err)
			}
		})

		t.Run(tc.entityType+"/"+tc.key+"/a non-string value", func(t *testing.T) {
			err := tc.build(valueFor(tc.key, 7)).VerifyMetadata()
			if err == nil {
				t.Fatalf("[%s] expected a non-string algorithm to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("[%s] expected the error to name %q, got %v", tc.reference, tc.key, err)
			}
		})

		if !tc.noneAllowed {
			t.Run(tc.entityType+"/"+tc.key+"/none in mixed case", func(t *testing.T) {
				if err := tc.build(valueFor(tc.key, "None")).VerifyMetadata(); err == nil {
					t.Fatalf("[%s] expected a mixed case 'None' to be refused", tc.reference)
				}
			})
		}
	}
}

func TestVerifyAlgClaim_Shape(t *testing.T) {
	tests := []struct {
		name      string
		value     any
		allowNone bool
		expectErr string
	}{
		{name: "a non-string value is refused", value: 7, expectErr: "must be a string"},
		{name: "a real algorithm is accepted", value: "ES256"},
		{name: "none is refused when not allowed", value: "none", expectErr: "must not be the value 'none'"},
		{name: "none is accepted when allowed", value: "none", allowNone: true},
		{name: "a null value is ignored", value: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyAlgClaim(map[string]any{"alg_under_test": tc.value}, "alg_under_test", tc.allowNone)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected an error containing %q, got %v", tc.expectErr, err)
			}
		})
	}
}
