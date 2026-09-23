package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestMetadataPolicy_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		policy   MetadataPolicy
		expected string
		err      error
	}{
		{
			name: "valid metadata policy with varied operators",
			policy: MetadataPolicy{
				FederationMetadata: map[string]PolicyOperators{
					"key1": {Metadata: []MetadataPolicyOperator{
						Add{operatorValue: []any{"foo", "bar"}},
						SubsetOf{operatorValue: []any{"foo", "bar", "baz", "bin"}},
						SupersetOf{operatorValue: []any{"foo", "bar"}},
					}},
				},
				OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
					"key2": {Metadata: []MetadataPolicyOperator{
						SubsetOf{operatorValue: []any{"alpha", "beta", "gamma"}},
						Default{operatorValue: "alpha"},
						Add{operatorValue: []any{"alpha", "gamma"}},
					}},
				},
				OpenIDConnectOpenIDProviderMetadata: map[string]PolicyOperators{
					"key3": {Metadata: []MetadataPolicyOperator{
						SupersetOf{operatorValue: []any{"test1", "test2"}},
						Essential{operatorValue: true},
						SubsetOf{operatorValue: []any{"test1", "test2", "test3"}},
					}},
					"key4": {Metadata: []MetadataPolicyOperator{
						Value{operatorValue: "foo"},
					}},
				},
			},
			expected: `{"federation_entity":{"key1":{"add":["foo","bar"],"subset_of":["foo","bar","baz","bin"],"superset_of":["foo","bar"]}},"openid_relying_party":{"key2":{"add":["alpha","gamma"],"subset_of":["alpha","beta","gamma"],"default":"alpha"}},"openid_provider":{"key3":{"subset_of":["test1","test2","test3"],"superset_of":["test1","test2"],"essential":true},"key4":{"value":"foo"}}}`,
			err:      nil,
		},
		{
			name:     "empty metadata policy",
			policy:   MetadataPolicy{},
			expected: `{}`,
			err:      nil,
		},
		{
			name: "metadata policy with an unrecognised entity type",
			policy: MetadataPolicy{
				FederationMetadata: map[string]PolicyOperators{
					"organization_name": {Metadata: []MetadataPolicyOperator{Value{operatorValue: "Example"}}},
				},
				Extensions: map[string]map[string]PolicyOperators{
					"openid_verifier_provider": {
						"organization_name": {Metadata: []MetadataPolicyOperator{Value{operatorValue: "Example Verifier"}}},
					},
				},
			},
			expected: `{"federation_entity":{"organization_name":{"value":"Example"}},"openid_verifier_provider":{"organization_name":{"value":"Example Verifier"}}}`,
			err:      nil,
		},
		{
			name: "empty metadata policy holders",
			policy: MetadataPolicy{
				FederationMetadata:                  map[string]PolicyOperators{},
				OpenIDRelyingPartyMetadata:          map[string]PolicyOperators{},
				OpenIDConnectOpenIDProviderMetadata: map[string]PolicyOperators{},
			},
			expected: `{"federation_entity":{},"openid_relying_party":{},"openid_provider":{}}`,
			err:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.policy)
			if (err != nil || tt.err != nil) && (err == nil || tt.err == nil || err.Error() != tt.err.Error()) {
				t.Fatalf("expected error %v, got error %v", tt.err, err)
			}

			var expectedMap, resultMap map[string]any
			if err := json.Unmarshal([]byte(tt.expected), &expectedMap); err != nil {
				t.Fatalf("failed to unmarshal expected body: %v", err)
			}
			if err := json.Unmarshal(data, &resultMap); err != nil {
				t.Fatalf("failed to unmarshal result body: %v", err)
			}

			if diff := cmp.Diff(expectedMap, resultMap, cmpopts.SortSlices(func(x, y any) bool {
				if sx, ok := x.(string); ok {
					if sy, ok := y.(string); ok {
						return sx < sy
					}
				}
				return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
			})); diff != "" {
				t.Errorf("mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestMetadata_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected Metadata
		wantErr  bool
	}{
		{
			name: "valid JSON with all three metadata types",
			json: `{
				"federation_entity": {
					"federation_fetch_endpoint": "https://example.com/fetch",
					"federation_list_endpoint": "https://example.com/list",
					"federation_resolve_endpoint": "https://example.com/resolve",
					"federation_trust_mark_status_endpoint": "https://example.com/status",
					"federation_trust_mark_list_endpoint": "https://example.com/list",
					"federation_trust_mark_endpoint": "https://example.com/trust",
					"federation_historical_keys_endpoint": "https://example.com/keys"
				},
				"openid_relying_party": {
					"redirect_uris": ["https://example.com/callback"],
					"client_registration_types": ["automatic"]
				},
				"openid_provider": {
					"response_types_supported": ["code"],
					"subject_types_supported": ["public"],
					"id_token_signing_alg_values_supported": ["RS256"],
					"client_registration_types_supported": ["automatic"],
					"issuer": "https://example.com",
					"authorization_endpoint": "https://example.com/auth",
					"token_endpoint": "https://example.com/token",
					"jwks_uri": "https://example.com/jwks"
				}
			}`,
			expected: Metadata{
				FederationMetadata: &FederationMetadata{
					"federation_fetch_endpoint":             "https://example.com/fetch",
					"federation_list_endpoint":              "https://example.com/list",
					"federation_resolve_endpoint":           "https://example.com/resolve",
					"federation_trust_mark_status_endpoint": "https://example.com/status",
					"federation_trust_mark_list_endpoint":   "https://example.com/list",
					"federation_trust_mark_endpoint":        "https://example.com/trust",
					"federation_historical_keys_endpoint":   "https://example.com/keys",
				},
				OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
					"redirect_uris":             []interface{}{"https://example.com/callback"},
					"client_registration_types": []interface{}{"automatic"},
				},
				OpenIDConnectOpenIDProviderMetadata: &OpenIDConnectOpenIDProviderMetadata{
					"response_types_supported":              []interface{}{"code"},
					"subject_types_supported":               []interface{}{"public"},
					"id_token_signing_alg_values_supported": []interface{}{"RS256"},
					"client_registration_types_supported":   []interface{}{"automatic"},
					"issuer":                                "https://example.com",
					"authorization_endpoint":                "https://example.com/auth",
					"token_endpoint":                        "https://example.com/token",
					"jwks_uri":                              "https://example.com/jwks",
				},
			},
			wantErr: false,
		},
		{
			name: "valid JSON with only federation metadata",
			json: `{
				"federation_entity": {
					"federation_fetch_endpoint": "https://example.com/fetch",
					"federation_list_endpoint": "https://example.com/list",
					"federation_resolve_endpoint": "https://example.com/resolve",
					"federation_trust_mark_status_endpoint": "https://example.com/status",
					"federation_trust_mark_list_endpoint": "https://example.com/list",
					"federation_trust_mark_endpoint": "https://example.com/trust",
					"federation_historical_keys_endpoint": "https://example.com/keys"
				}
			}`,
			expected: Metadata{
				FederationMetadata: &FederationMetadata{
					"federation_fetch_endpoint":             "https://example.com/fetch",
					"federation_list_endpoint":              "https://example.com/list",
					"federation_resolve_endpoint":           "https://example.com/resolve",
					"federation_trust_mark_status_endpoint": "https://example.com/status",
					"federation_trust_mark_list_endpoint":   "https://example.com/list",
					"federation_trust_mark_endpoint":        "https://example.com/trust",
					"federation_historical_keys_endpoint":   "https://example.com/keys",
				},
			},
			wantErr: false,
		},
		{
			name:     "empty JSON object",
			json:     `{}`,
			expected: Metadata{},
			wantErr:  false,
		},
		{
			name:     "invalid JSON",
			json:     `{invalid json}`,
			expected: Metadata{},
			wantErr:  true,
		},
		{
			name: "invalid federation metadata - non-HTTPS endpoint",
			json: `{
				"federation_entity": {
					"federation_fetch_endpoint": "http://example.com/fetch",
					"federation_list_endpoint": "https://example.com/list",
					"federation_resolve_endpoint": "https://example.com/resolve",
					"federation_trust_mark_status_endpoint": "https://example.com/status",
					"federation_trust_mark_list_endpoint": "https://example.com/list",
					"federation_trust_mark_endpoint": "https://example.com/trust",
					"federation_historical_keys_endpoint": "https://example.com/keys",
					"endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"]
				}
			}`,
			expected: Metadata{},
			wantErr:  true,
		},
		{
			name: "invalid openid relying party metadata - missing required field",
			json: `{
				"openid_relying_party": {
					"client_registration_types": ["automatic"]
				}
			}`,
			expected: Metadata{},
			wantErr:  true,
		},
		{
			name: "invalid openid provider metadata - missing conditionally required token_endpoint",
			json: `{
				"openid_provider": {
					"response_types_supported": ["code"],
					"subject_types_supported": ["public"],
					"id_token_signing_alg_values_supported": ["RS256"],
					"client_registration_types_supported": ["automatic"],
					"issuer": "https://example.com",
					"authorization_endpoint": "https://example.com/auth",
					"jwks_uri": "https://example.com/jwks"
				}
			}`,
			expected: Metadata{},
			wantErr:  true,
		},
		{
			name: "unrecognised entity type is captured as an extension",
			json: `{
				"openid_verifier_provider": {
					"vp_formats_supported": {"dc+sd-jwt": {}}
				}
			}`,
			expected: Metadata{
				Extensions: map[string]map[string]any{
					"openid_verifier_provider": {
						"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unrecognised entity types coexist with built-in entity types",
			json: `{
				"federation_entity": {
					"organization_name": "Example"
				},
				"openid_verifier_provider": {
					"vp_formats_supported": {"dc+sd-jwt": {}}
				}
			}`,
			expected: Metadata{
				FederationMetadata: &FederationMetadata{
					"organization_name": "Example",
				},
				Extensions: map[string]map[string]any{
					"openid_verifier_provider": {
						"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "malformed unrecognised entity type is rejected",
			json: `{
				"openid_verifier_provider": "not-an-object"
			}`,
			expected: Metadata{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m Metadata
			err := json.Unmarshal([]byte(tt.json), &m)

			if (err != nil) != tt.wantErr {
				t.Errorf("Metadata.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Compare the unmarshaled metadata with the expected metadata
				if !reflect.DeepEqual(m, tt.expected) {
					t.Errorf("Metadata.UnmarshalJSON() = %v, want %v", m, tt.expected)
				}
			}
		})
	}
}

func TestEntityStatement_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name                  string
		json                  string
		expected              EntityStatement
		wantErr               bool
		expectInvalidMetadata bool
	}{
		{
			name: "valid entity configuration with trust marks and issuers",
			json: `{
				"iss": "https://issuer.example.com",
				"sub": "https://subject.example.com",
				"iat": 1710000000,
				"exp": 4102444800,
				"authority_hints": ["https://anchor.example.com"],
				"jwks": {"keys": [{"kid": "test-key", "kty": "RSA"}]},
				"trust_marks": [{"trust_mark_type": "https://example.com/trust-mark", "trust_mark": "jwt-value"}],
				"trust_mark_issuers": {
					"https://example.com/trust-mark": ["https://issuer.example.com"]
				},
				"trust_mark_owners": {
					"https://example.com/trust-mark": {
						"sub": "https://issuer.example.com",
						"jwks": {"keys": []}
					}
				},
				"source_endpoint": "https://subject.example.com/source"
			}`,
			expected: EntityStatement{
				Iss:            EntityIdentifier("https://issuer.example.com"),
				Sub:            EntityIdentifier("https://subject.example.com"),
				Iat:            1710000000,
				Exp:            4102444800,
				AuthorityHints: []EntityIdentifier{EntityIdentifier("https://anchor.example.com")},
				JWKs:           josemodel.Jwks{Keys: []map[string]any{{"kid": "test-key", "kty": "RSA"}}},
				TrustMarks:     []TrustMarkHolder{{TrustMarkType: "https://example.com/trust-mark", TrustMark: "jwt-value"}},
				TrustMarkIssuers: map[string][]EntityIdentifier{
					"https://example.com/trust-mark": {EntityIdentifier("https://issuer.example.com")},
				},
				TrustMarkOwners: map[string]any{
					"https://example.com/trust-mark": map[string]any{
						"sub":  "https://issuer.example.com",
						"jwks": map[string]any{"keys": []any{}},
					},
				},
				SourceEndpoint: "https://subject.example.com/source",
			},
			wantErr: false,
		},
		{
			name: "invalid trust mark issuers payload",
			json: `{
				"iss": "https://issuer.example.com",
				"sub": "https://subject.example.com",
				"iat": 1710000000,
				"exp": 1710003600,
				"jwks": {"keys": []},
				"trust_mark_issuers": {"https://example.com/trust-mark": "not-an-array"}
			}`,
			wantErr: true,
		},
		{
			name: "invalid metadata claim wraps invalid metadata sentinel",
			json: `{
				"iss": "https://issuer.example.com",
				"sub": "https://subject.example.com",
				"iat": 1710000000,
				"exp": 4102444800,
				"jwks": {"keys": [{"kid": "test-key", "kty": "RSA"}]},
				"metadata": {
					"openid_relying_party": {
						"scope": "openid profile"
					}
				}
			}`,
			wantErr:               true,
			expectInvalidMetadata: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got EntityStatement
			err := json.Unmarshal([]byte(tt.json), &got)

			if (err != nil) != tt.wantErr {
				t.Fatalf("EntityStatement.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if tt.expectInvalidMetadata && !errors.Is(err, ErrInvalidMetadata) {
					t.Fatalf("expected error to wrap ErrInvalidMetadata")
				}
				return
			}

			if diff := cmp.Diff(tt.expected, got, cmpopts.IgnoreFields(josemodel.Jwks{}, "Opts")); diff != "" {
				t.Errorf("EntityStatement.UnmarshalJSON() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
