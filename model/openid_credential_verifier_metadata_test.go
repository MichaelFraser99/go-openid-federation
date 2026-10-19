package model

import (
	"testing"
)

func TestOpenIDCredentialVerifierMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDCredentialVerifierMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OpenIDCredentialVerifierMetadata{},
			wantErr:  false,
		},
		"valid metadata": {
			metadata: OpenIDCredentialVerifierMetadata{
				"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
			},
			wantErr: false,
		},
		"missing vp_formats_supported is not a syntax fault": {
			metadata: OpenIDCredentialVerifierMetadata{
				"redirect_uris": []any{"https://verifier.example.com/cb"},
			},
			wantErr: false,
		},
		"vp_formats_supported must be object": {
			metadata: OpenIDCredentialVerifierMetadata{
				"vp_formats_supported": []any{"dc+sd-jwt"},
			},
			wantErr: true,
		},
		"redirect_uris must be array of strings": {
			metadata: OpenIDCredentialVerifierMetadata{
				"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
				"redirect_uris":        "https://verifier.example.com/cb",
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

func TestOpenIDCredentialVerifierMetadata_VerifyResolvedMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDCredentialVerifierMetadata
		wantErr  bool
	}{
		"an empty object does not satisfy a type that requires parameters": {
			metadata: OpenIDCredentialVerifierMetadata{},
			wantErr:  true,
		},
		"vp_formats_supported supplied": {
			metadata: OpenIDCredentialVerifierMetadata{
				"vp_formats_supported": map[string]any{"jwt_vc": map[string]any{}},
			},
			wantErr: false,
		},
		"missing vp_formats_supported": {
			metadata: OpenIDCredentialVerifierMetadata{
				"redirect_uris": []any{"https://verifier.example.com/cb"},
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
