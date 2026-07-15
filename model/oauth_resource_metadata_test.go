package model

import (
	"testing"
)

func TestOAuthResourceMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OAuthResourceMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OAuthResourceMetadata{},
			wantErr:  false,
		},
		"valid minimal metadata": {
			metadata: OAuthResourceMetadata{
				"resource": "https://resource.example.com",
			},
			wantErr: false,
		},
		"missing resource": {
			metadata: OAuthResourceMetadata{
				"scopes_supported": []any{"read"},
			},
			wantErr: true,
		},
		"resource must be https": {
			metadata: OAuthResourceMetadata{
				"resource": "http://resource.example.com",
			},
			wantErr: true,
		},
		"resource must not contain fragment": {
			metadata: OAuthResourceMetadata{
				"resource": "https://resource.example.com#frag",
			},
			wantErr: true,
		},
		"resource may contain query": {
			metadata: OAuthResourceMetadata{
				"resource": "https://resource.example.com?tenant=1",
			},
			wantErr: false,
		},
		"jwks_uri must be https": {
			metadata: OAuthResourceMetadata{
				"resource": "https://resource.example.com",
				"jwks_uri": "http://resource.example.com/jwks",
			},
			wantErr: true,
		},
		"resource_signing_alg_values_supported must not contain none": {
			metadata: OAuthResourceMetadata{
				"resource":                              "https://resource.example.com",
				"resource_signing_alg_values_supported": []any{"RS256", "none"},
			},
			wantErr: true,
		},
		"resource_signing_alg_values_supported without none is valid": {
			metadata: OAuthResourceMetadata{
				"resource":                              "https://resource.example.com",
				"resource_signing_alg_values_supported": []any{"RS256", "ES256"},
			},
			wantErr: false,
		},
		"authorization_servers must be array of strings": {
			metadata: OAuthResourceMetadata{
				"resource":              "https://resource.example.com",
				"authorization_servers": "https://as.example.com",
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
