package model

import (
	"strings"
	"testing"
)

func TestOAuthAuthorizationServerMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OAuthAuthorizationServerMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OAuthAuthorizationServerMetadata{},
			wantErr:  false,
		},
		"valid minimal metadata": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com",
				"response_types_supported": []any{"code"},
			},
			wantErr: false,
		},
		"missing issuer is not a syntax fault": {
			metadata: OAuthAuthorizationServerMetadata{
				"response_types_supported": []any{"code"},
			},
			wantErr: false,
		},
		"missing response_types_supported is not a syntax fault": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer": "https://as.example.com",
			},
			wantErr: false,
		},
		"issuer must be https": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "http://as.example.com",
				"response_types_supported": []any{"code"},
			},
			wantErr: true,
		},
		"issuer must not contain query": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com?foo=bar",
				"response_types_supported": []any{"code"},
			},
			wantErr: true,
		},
		"issuer must not contain fragment": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com#frag",
				"response_types_supported": []any{"code"},
			},
			wantErr: true,
		},
		"issuer with path is valid": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com/tenant1",
				"response_types_supported": []any{"code"},
			},
			wantErr: false,
		},
		"response_types_supported must be array of strings": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com",
				"response_types_supported": "code",
			},
			wantErr: true,
		},
		"jwks_uri must be https": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com",
				"response_types_supported": []any{"code"},
				"jwks_uri":                 "http://as.example.com/jwks",
			},
			wantErr: true,
		},
		"jwks_uri with query is valid": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com",
				"response_types_supported": []any{"code"},
				"jwks_uri":                 "https://as.example.com/jwks?v=1",
			},
			wantErr: false,
		},
		"grant_types_supported must be array of strings": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer":                   "https://as.example.com",
				"response_types_supported": []any{"code"},
				"grant_types_supported":    []any{"authorization_code", 1},
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyMetadata()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOAuthAuthorizationServerMetadata_VerifyResolvedMetadata(t *testing.T) {
	base := func(extra map[string]any) OAuthAuthorizationServerMetadata {
		m := OAuthAuthorizationServerMetadata{
			"issuer":                   "https://as.example.com",
			"response_types_supported": []any{"code"},
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	endpoints := func(extra map[string]any) OAuthAuthorizationServerMetadata {
		m := base(map[string]any{
			"authorization_endpoint": "https://as.example.com/authorize",
			"token_endpoint":         "https://as.example.com/token",
		})
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	tests := map[string]struct {
		reference string
		metadata  OAuthAuthorizationServerMetadata
		says      string
	}{
		"an empty object does not satisfy a type that requires parameters": {
			reference: "RFC 8414 2",
			metadata:  OAuthAuthorizationServerMetadata{},
			says:      "missing required 'issuer' claim",
		},
		"missing issuer": {
			reference: "RFC 8414 2",
			metadata:  OAuthAuthorizationServerMetadata{"response_types_supported": []any{"code"}},
			says:      "missing required 'issuer' claim",
		},
		"missing response_types_supported": {
			reference: "RFC 8414 2",
			metadata:  OAuthAuthorizationServerMetadata{"issuer": "https://as.example.com"},
			says:      "missing required 'response_types_supported' claim",
		},
		"both endpoints with the default grant types": {
			reference: "RFC 8414 2",
			metadata:  endpoints(nil),
		},
		"no endpoints with the default grant types": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata:  base(nil),
			says:      "missing required 'authorization_endpoint' claim",
		},
		"no token_endpoint with the default grant types": {
			reference: "RFC 8414 2 token_endpoint",
			metadata:  base(map[string]any{"authorization_endpoint": "https://as.example.com/authorize"}),
			says:      "missing required 'token_endpoint' claim",
		},
		"no authorization_endpoint for authorization_code": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata: base(map[string]any{
				"token_endpoint":        "https://as.example.com/token",
				"grant_types_supported": []any{"authorization_code"},
			}),
			says: "missing required 'authorization_endpoint' claim",
		},
		"no authorization_endpoint for implicit": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata:  base(map[string]any{"grant_types_supported": []any{"implicit"}}),
			says:      "missing required 'authorization_endpoint' claim",
		},
		"no token_endpoint when implicit is the only grant type": {
			reference: "RFC 8414 2 token_endpoint",
			metadata: base(map[string]any{
				"authorization_endpoint": "https://as.example.com/authorize",
				"grant_types_supported":  []any{"implicit"},
			}),
		},
		"no token_endpoint when implicit is supported beside another grant type": {
			reference: "RFC 8414 2 token_endpoint",
			metadata: base(map[string]any{
				"authorization_endpoint": "https://as.example.com/authorize",
				"grant_types_supported":  []any{"implicit", "client_credentials"},
			}),
			says: "missing required 'token_endpoint' claim",
		},
		"no authorization_endpoint for client_credentials alone": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata: base(map[string]any{
				"token_endpoint":        "https://as.example.com/token",
				"grant_types_supported": []any{"client_credentials"},
			}),
		},
		"no authorization_endpoint for an extension grant type alone": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata: base(map[string]any{
				"token_endpoint":        "https://as.example.com/token",
				"grant_types_supported": []any{"urn:ietf:params:oauth:grant-type:device_code"},
			}),
		},
		"no authorization_endpoint for a grant type differing from authorization_code only in case": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata: base(map[string]any{
				"token_endpoint":        "https://as.example.com/token",
				"grant_types_supported": []any{"Authorization_Code"},
			}),
		},
		"no token_endpoint for an empty grant_types_supported": {
			reference: "RFC 8414 2 token_endpoint",
			metadata:  base(map[string]any{"grant_types_supported": []any{}}),
			says:      "missing required 'token_endpoint' claim",
		},
		"a token_endpoint and an empty grant_types_supported": {
			reference: "RFC 8414 2 authorization_endpoint",
			metadata: base(map[string]any{
				"token_endpoint":        "https://as.example.com/token",
				"grant_types_supported": []any{},
			}),
		},
		"private_key_jwt at the token endpoint without its signing algorithms": {
			reference: "RFC 8414 2 token_endpoint_auth_signing_alg_values_supported",
			metadata:  endpoints(map[string]any{"token_endpoint_auth_methods_supported": []any{"client_secret_basic", "private_key_jwt"}}),
			says:      "missing required 'token_endpoint_auth_signing_alg_values_supported' claim",
		},
		"client_secret_jwt at the token endpoint without its signing algorithms": {
			reference: "RFC 8414 2 token_endpoint_auth_signing_alg_values_supported",
			metadata:  endpoints(map[string]any{"token_endpoint_auth_methods_supported": []any{"client_secret_jwt"}}),
			says:      "missing required 'token_endpoint_auth_signing_alg_values_supported' claim",
		},
		"private_key_jwt at the token endpoint with its signing algorithms": {
			reference: "RFC 8414 2 token_endpoint_auth_signing_alg_values_supported",
			metadata: endpoints(map[string]any{
				"token_endpoint_auth_methods_supported":            []any{"private_key_jwt"},
				"token_endpoint_auth_signing_alg_values_supported": []any{"ES256"},
			}),
		},
		"private_key_jwt at the token endpoint with only the revocation signing algorithms": {
			reference: "RFC 8414 2 token_endpoint_auth_signing_alg_values_supported",
			metadata: endpoints(map[string]any{
				"token_endpoint_auth_methods_supported":                 []any{"private_key_jwt"},
				"revocation_endpoint_auth_signing_alg_values_supported": []any{"ES256"},
			}),
			says: "missing required 'token_endpoint_auth_signing_alg_values_supported' claim",
		},
		"token endpoint methods that use no JWT": {
			reference: "RFC 8414 2 token_endpoint_auth_signing_alg_values_supported",
			metadata:  endpoints(map[string]any{"token_endpoint_auth_methods_supported": []any{"client_secret_basic", "tls_client_auth"}}),
		},
		"a token endpoint method differing from private_key_jwt only in case": {
			reference: "RFC 8414 2 token_endpoint_auth_signing_alg_values_supported",
			metadata:  endpoints(map[string]any{"token_endpoint_auth_methods_supported": []any{"Private_Key_JWT"}}),
		},
		"private_key_jwt at the revocation endpoint without its signing algorithms": {
			reference: "RFC 8414 2 revocation_endpoint_auth_signing_alg_values_supported",
			metadata:  endpoints(map[string]any{"revocation_endpoint_auth_methods_supported": []any{"private_key_jwt"}}),
			says:      "missing required 'revocation_endpoint_auth_signing_alg_values_supported' claim",
		},
		"client_secret_jwt at the revocation endpoint with its signing algorithms": {
			reference: "RFC 8414 2 revocation_endpoint_auth_signing_alg_values_supported",
			metadata: endpoints(map[string]any{
				"revocation_endpoint_auth_methods_supported":            []any{"client_secret_jwt"},
				"revocation_endpoint_auth_signing_alg_values_supported": []any{"HS256"},
			}),
		},
		"client_secret_jwt at the introspection endpoint without its signing algorithms": {
			reference: "RFC 8414 2 introspection_endpoint_auth_signing_alg_values_supported",
			metadata:  endpoints(map[string]any{"introspection_endpoint_auth_methods_supported": []any{"client_secret_jwt"}}),
			says:      "missing required 'introspection_endpoint_auth_signing_alg_values_supported' claim",
		},
		"private_key_jwt at the introspection endpoint with its signing algorithms": {
			reference: "RFC 8414 2 introspection_endpoint_auth_signing_alg_values_supported",
			metadata: endpoints(map[string]any{
				"introspection_endpoint_auth_methods_supported":            []any{"private_key_jwt"},
				"introspection_endpoint_auth_signing_alg_values_supported": []any{"ES256"},
			}),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyResolvedMetadata()
			if tt.says == "" {
				if err != nil {
					t.Errorf("[%s] expected the metadata to be accepted, got %v", tt.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected a refusal containing %q, got none", tt.reference, tt.says)
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("[%s] expected a refusal containing %q, got %v", tt.reference, tt.says, err)
			}
		})
	}
}
