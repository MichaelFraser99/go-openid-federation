package model

import (
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
		"missing issuer": {
			metadata: OAuthAuthorizationServerMetadata{
				"response_types_supported": []any{"code"},
			},
			wantErr: true,
		},
		"missing response_types_supported": {
			metadata: OAuthAuthorizationServerMetadata{
				"issuer": "https://as.example.com",
			},
			wantErr: true,
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
