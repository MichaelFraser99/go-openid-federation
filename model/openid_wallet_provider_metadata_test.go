package model

import (
	"testing"
)

func TestOpenIDWalletProviderMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDWalletProviderMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OpenIDWalletProviderMetadata{},
			wantErr:  false,
		},
		"valid metadata": {
			metadata: OpenIDWalletProviderMetadata{
				"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
			},
			wantErr: false,
		},
		"missing vp_formats_supported": {
			metadata: OpenIDWalletProviderMetadata{
				"client_id_prefixes_supported": []any{"redirect_uri"},
			},
			wantErr: true,
		},
		"vp_formats_supported must be object": {
			metadata: OpenIDWalletProviderMetadata{
				"vp_formats_supported": "dc+sd-jwt",
			},
			wantErr: true,
		},
		"client_id_prefixes_supported must not be empty": {
			metadata: OpenIDWalletProviderMetadata{
				"vp_formats_supported":         map[string]any{"dc+sd-jwt": map[string]any{}},
				"client_id_prefixes_supported": []any{},
			},
			wantErr: true,
		},
		"client_id_prefixes_supported valid": {
			metadata: OpenIDWalletProviderMetadata{
				"vp_formats_supported":         map[string]any{"dc+sd-jwt": map[string]any{}},
				"client_id_prefixes_supported": []any{"redirect_uri", "x509_san_dns"},
			},
			wantErr: false,
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
