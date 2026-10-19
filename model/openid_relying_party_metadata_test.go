package model

import (
	"testing"
)

func TestOpenIDRelyingPartyMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDRelyingPartyMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OpenIDRelyingPartyMetadata{},
			wantErr:  false,
		},
		"valid minimal metadata": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://rp.example.com/cb"},
			},
			wantErr: false,
		},
		"missing redirect_uris is not a syntax fault": {
			metadata: OpenIDRelyingPartyMetadata{
				"client_registration_types": []any{"automatic"},
			},
			wantErr: false,
		},
		"client_registration_types not required": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://rp.example.com/cb"},
			},
			wantErr: false,
		},
		"redirect_uris must be array of strings": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris": "https://rp.example.com/cb",
			},
			wantErr: true,
		},
		"jwks and jwks_uri must not be used together": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://rp.example.com/cb"},
				"jwks":          map[string]any{"keys": []any{}},
				"jwks_uri":      "https://rp.example.com/jwks",
			},
			wantErr: true,
		},
		"jwks alone is valid": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://rp.example.com/cb"},
				"jwks":          map[string]any{"keys": []any{}},
			},
			wantErr: false,
		},
		"signed_jwks_uri must be https": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris":   []any{"https://rp.example.com/cb"},
				"signed_jwks_uri": "http://rp.example.com/jwks.jose",
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

func TestOpenIDRelyingPartyMetadata_VerifyResolvedMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDRelyingPartyMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OpenIDRelyingPartyMetadata{},
			wantErr:  false,
		},
		"redirect_uris supplied": {
			metadata: OpenIDRelyingPartyMetadata{
				"redirect_uris": []any{"https://rp.example.com/cb"},
			},
			wantErr: false,
		},
		"missing redirect_uris": {
			metadata: OpenIDRelyingPartyMetadata{
				"client_registration_types": []any{"automatic"},
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyResolvedMetadata()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyResolvedMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
