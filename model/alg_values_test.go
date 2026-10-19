package model

import (
	"strings"
	"testing"
)

func TestSigningAlgorithmClaimsRejectNone(t *testing.T) {
	baseProvider := func(extra map[string]any) OpenIDConnectOpenIDProviderMetadata {
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

	tests := []struct {
		name      string
		reference string
		metadata  EntityTypeIdentifier
		expectErr string
	}{
		{
			name:      "provider token endpoint auth signing algorithms reject none",
			reference: "OIDC Discovery 3",
			metadata:  baseProvider(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []any{"RS256", "none"}}),
			expectErr: "must not contain the value 'none'",
		},
		{
			name:      "provider request object signing algorithms reject none",
			reference: "OIDC Discovery 3",
			metadata:  baseProvider(map[string]any{"request_object_signing_alg_values_supported": []any{"none"}}),
			expectErr: "must not contain the value 'none'",
		},
		{
			name:      "provider id token signing algorithms permit none",
			reference: "OIDC Discovery 3",
			metadata:  baseProvider(map[string]any{"id_token_signing_alg_values_supported": []any{"ES256", "none"}}),
		},
		{
			name:      "provider token endpoint auth signing algorithms without none are valid",
			reference: "OIDC Discovery 3",
			metadata:  baseProvider(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []any{"RS256"}}),
		},
		{
			name:      "authorization server token endpoint auth signing algorithms reject none",
			reference: "RFC 8414 2",
			metadata:  OAuthAuthorizationServerMetadata{"issuer": "https://as.example.com", "response_types_supported": []any{"code"}, "token_endpoint_auth_signing_alg_values_supported": []any{"none"}},
			expectErr: "must not contain the value 'none'",
		},
		{
			name:      "authorization server introspection auth signing algorithms reject none",
			reference: "RFC 8414 2",
			metadata:  OAuthAuthorizationServerMetadata{"issuer": "https://as.example.com", "response_types_supported": []any{"code"}, "introspection_endpoint_auth_signing_alg_values_supported": []any{"none"}},
			expectErr: "must not contain the value 'none'",
		},
		{
			name:      "relying party token endpoint auth signing algorithm rejects none",
			reference: "OIDC Registration 2",
			metadata:  OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://rp.example.com/cb"}, "token_endpoint_auth_signing_alg": "none"},
			expectErr: "must not be the value 'none'",
		},
		{
			name:      "relying party id token signed response algorithm rejects none",
			reference: "OIDC Registration 2",
			metadata:  OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://rp.example.com/cb"}, "id_token_signed_response_alg": "none"},
			expectErr: "must not be the value 'none'",
		},
		{
			name:      "relying party token endpoint auth signing algorithm accepts a real algorithm",
			reference: "OIDC Registration 2",
			metadata:  OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://rp.example.com/cb"}, "token_endpoint_auth_signing_alg": "ES256"},
		},
		{
			name:      "relying party token endpoint auth signing algorithm must be a string",
			reference: "OIDC Registration 2",
			metadata:  OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://rp.example.com/cb"}, "token_endpoint_auth_signing_alg": 7},
			expectErr: "must be a string",
		},
		{
			name:      "oauth client token endpoint auth signing algorithm rejects none",
			reference: "RFC 7591 2",
			metadata:  OAuthClientMetadata{"token_endpoint_auth_signing_alg": "none"},
			expectErr: "must not be the value 'none'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.metadata.VerifyMetadata()
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the metadata to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error containing %q, got accepted metadata", tc.reference, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
