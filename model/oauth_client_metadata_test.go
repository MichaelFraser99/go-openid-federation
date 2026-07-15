package model

import (
	"testing"
)

func TestOAuthClientMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OAuthClientMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OAuthClientMetadata{},
			wantErr:  false,
		},
		"no required fields": {
			metadata: OAuthClientMetadata{
				"client_name": "Example",
			},
			wantErr: false,
		},
		"valid redirect_uris": {
			metadata: OAuthClientMetadata{
				"redirect_uris": []any{"https://client.example.com/cb"},
			},
			wantErr: false,
		},
		"redirect_uris must be array of strings": {
			metadata: OAuthClientMetadata{
				"redirect_uris": "https://client.example.com/cb",
			},
			wantErr: true,
		},
		"grant_types must be array of strings": {
			metadata: OAuthClientMetadata{
				"grant_types": []any{"authorization_code", 2},
			},
			wantErr: true,
		},
		"jwks must be an object": {
			metadata: OAuthClientMetadata{
				"jwks": "not-an-object",
			},
			wantErr: true,
		},
		"jwks and jwks_uri together permitted per RFC 7591": {
			metadata: OAuthClientMetadata{
				"jwks":     map[string]any{"keys": []any{}},
				"jwks_uri": "https://client.example.com/jwks",
			},
			wantErr: false,
		},
		"jwks_uri must be https": {
			metadata: OAuthClientMetadata{
				"jwks_uri": "http://client.example.com/jwks",
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
