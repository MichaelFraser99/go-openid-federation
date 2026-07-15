package model

import (
	"testing"
)

func TestOpenIDProviderMetadata_VerifyMetadata(t *testing.T) {
	base := func() OpenIDConnectOpenIDProviderMetadata {
		return OpenIDConnectOpenIDProviderMetadata{
			"issuer":                                "https://op.example.com",
			"authorization_endpoint":                "https://op.example.com/auth",
			"token_endpoint":                        "https://op.example.com/token",
			"jwks_uri":                              "https://op.example.com/jwks",
			"response_types_supported":              []any{"code"},
			"subject_types_supported":               []any{"public"},
			"id_token_signing_alg_values_supported": []any{"RS256"},
		}
	}

	tests := map[string]struct {
		metadata OpenIDConnectOpenIDProviderMetadata
		wantErr  bool
	}{
		"empty metadata is valid": {
			metadata: OpenIDConnectOpenIDProviderMetadata{},
			wantErr:  false,
		},
		"valid metadata": {
			metadata: base(),
			wantErr:  false,
		},
		"missing issuer": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				delete(m, "issuer")
				return m
			}(),
			wantErr: true,
		},
		"missing jwks mechanism": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				delete(m, "jwks_uri")
				return m
			}(),
			wantErr: true,
		},
		"signed_jwks_uri satisfies key mechanism": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				delete(m, "jwks_uri")
				m["signed_jwks_uri"] = "https://op.example.com/jwks.jose"
				return m
			}(),
			wantErr: false,
		},
		"jwks by value satisfies key mechanism": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				delete(m, "jwks_uri")
				m["jwks"] = map[string]any{"keys": []any{}}
				return m
			}(),
			wantErr: false,
		},
		"token_endpoint required for code flow": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				delete(m, "token_endpoint")
				return m
			}(),
			wantErr: true,
		},
		"token_endpoint not required for implicit only": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				delete(m, "token_endpoint")
				m["response_types_supported"] = []any{"id_token", "id_token token"}
				return m
			}(),
			wantErr: false,
		},
		"client_registration_types_supported not required": {
			metadata: base(),
			wantErr:  false,
		},
		"issuer must not contain query": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				m["issuer"] = "https://op.example.com?x=1"
				return m
			}(),
			wantErr: true,
		},
		"authorization_endpoint must be https": {
			metadata: func() OpenIDConnectOpenIDProviderMetadata {
				m := base()
				m["authorization_endpoint"] = "http://op.example.com/auth"
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
