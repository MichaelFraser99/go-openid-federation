package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

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
					"token_endpoint": "https://example.com/token"
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
					"redirect_uris": ["https://example.com/callback"]
				}
			}`,
			expected: Metadata{},
			wantErr:  true,
		},
		{
			name: "invalid openid provider metadata - missing required field",
			json: `{
				"openid_provider": {
					"response_types_supported": ["code"],
					"subject_types_supported": ["public"],
					"id_token_signing_alg_values_supported": ["RS256"],
					"client_registration_types_supported": ["automatic"],
					"issuer": "https://example.com",
					"authorization_endpoint": "https://example.com/auth"
				}
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
