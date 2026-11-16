package model

import (
	"strings"
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
		"missing credential_issuer is not a syntax fault": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				delete(m, "credential_issuer")
				return m
			}(),
			wantErr: false,
		},
		"missing credential_endpoint is not a syntax fault": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				delete(m, "credential_endpoint")
				return m
			}(),
			wantErr: false,
		},
		"missing credential_configurations_supported is not a syntax fault": {
			metadata: func() OpenIDCredentialIssuerMetadata {
				m := base()
				delete(m, "credential_configurations_supported")
				return m
			}(),
			wantErr: false,
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

func TestOpenIDCredentialIssuerMetadata_VerifyResolvedMetadata(t *testing.T) {
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
		"an empty object does not satisfy a type that requires parameters": {
			metadata: OpenIDCredentialIssuerMetadata{},
			wantErr:  true,
		},
		"complete metadata": {
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

func TestOpenIDCredentialIssuerMetadata_AuthorizationServersAreEntityIdentifiers(t *testing.T) {
	with := func(servers any) OpenIDCredentialIssuerMetadata {
		return OpenIDCredentialIssuerMetadata{
			"credential_issuer":                   "https://issuer.example.com",
			"credential_endpoint":                 "https://issuer.example.com/credential",
			"credential_configurations_supported": map[string]any{"cfg": map[string]any{}},
			"authorization_servers":               servers,
		}
	}

	tests := map[string]struct {
		reference string
		servers   any
		says      string
	}{
		"one authorization server": {
			reference: "OpenID4VCI 12.2.4",
			servers:   []any{"https://as.example.com"},
		},
		"several authorization servers, with a port and a path": {
			reference: "OpenID4VCI 12.2.4",
			servers:   []any{"https://as.example.com", "https://as.example.com:8443/tenant"},
		},
		"authorization servers built as a Go slice": {
			reference: "OpenID4VCI 12.2.4",
			servers:   []string{"https://as.example.com"},
		},
		"an empty array": {
			reference: "OpenID4VCI 12.2.4",
			servers:   []any{},
			says:      "'authorization_servers' must not be empty",
		},
		"a string, not an array": {
			reference: "OpenID4VCI 12.2.4",
			servers:   "https://as.example.com",
			says:      "'authorization_servers' must be an array of strings",
		},
		"an entry that is not a string": {
			reference: "OpenID4VCI 12.2.4",
			servers:   []any{"https://as.example.com", 7},
			says:      "'authorization_servers' must be an array of strings",
		},
		"an entry over http": {
			reference: "RFC 8414 2",
			servers:   []any{"http://as.example.com"},
			says:      "'authorization_servers' must hold only entity identifiers",
		},
		"an entry with a query": {
			reference: "RFC 8414 2",
			servers:   []any{"https://as.example.com?tenant=1"},
			says:      "'authorization_servers' must hold only entity identifiers",
		},
		"an entry with a fragment": {
			reference: "RFC 8414 2",
			servers:   []any{"https://as.example.com#f"},
			says:      "'authorization_servers' must hold only entity identifiers",
		},
		"an entry that is not a URL": {
			reference: "Wallet draft 06 6.3.1",
			servers:   []any{"as.example.com"},
			says:      "'authorization_servers' must hold only entity identifiers",
		},
		"an entry with a raw space": {
			reference: "Wallet draft 06 6.3.1",
			servers:   []any{"https://as.example.com/a s"},
			says:      "'authorization_servers' must hold only entity identifiers",
		},
		"a valid entry after an invalid one": {
			reference: "Wallet draft 06 6.3.1",
			servers:   []any{"http://as.example.com", "https://as.example.com"},
			says:      "'authorization_servers' must hold only entity identifiers",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := with(tc.servers).VerifyMetadata()
			if tc.says == "" {
				if err != nil {
					t.Errorf("[%s] expected the metadata to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("[%s] expected a refusal containing %q, got %v", tc.reference, tc.says, err)
			}
		})
	}
}
