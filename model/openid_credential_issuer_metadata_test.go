package model

import (
	"testing"
)

func TestOpenIDCredentialIssuerMetadata_VerifyMetadata(t *testing.T) {
	base := func() OpenIDCredentialIssuerMetadata {
		return OpenIDCredentialIssuerMetadata{
			"credential_issuer":                   "https://issuer.example.com",
			"credential_endpoint":                 "https://issuer.example.com/credential",
			"credential_configurations_supported": map[string]any{"cfg": map[string]any{}},
		}
	}

	tests := map[string]struct {
		metadata OpenIDCredentialIssuerMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OpenIDCredentialIssuerMetadata{},
			wantErr:  false,
		},
		"valid metadata": {
			metadata: base(),
			wantErr:  false,
		},
		"missing credential_issuer": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				delete(m, "credential_issuer")
				return m
			}(),
			wantErr: true,
		},
		"missing credential_endpoint": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				delete(m, "credential_endpoint")
				return m
			}(),
			wantErr: true,
		},
		"missing credential_configurations_supported": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				delete(m, "credential_configurations_supported")
				return m
			}(),
			wantErr: true,
		},
		"credential_issuer must not contain query": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				m["credential_issuer"] = "https://issuer.example.com?x=1"
				return m
			}(),
			wantErr: true,
		},
		"credential_endpoint may contain query": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				m["credential_endpoint"] = "https://issuer.example.com/credential?v=1"
				return m
			}(),
			wantErr: false,
		},
		"credential_configurations_supported must be object": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				m["credential_configurations_supported"] = []any{"cfg"}
				return m
			}(),
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
