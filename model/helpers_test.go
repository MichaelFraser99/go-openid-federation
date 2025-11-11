package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_sortByPriority(t *testing.T) {
	tests := []struct {
		input    []MetadataPolicyOperator
		expected []MetadataPolicyOperator
	}{
		{
			input: []MetadataPolicyOperator{
				&Value{}, Add{}, Default{}, OneOf{}, SubsetOf{}, SupersetOf{}, Essential{},
			},
			expected: []MetadataPolicyOperator{
				&Value{}, Add{}, Default{}, OneOf{}, SubsetOf{}, SupersetOf{}, Essential{},
			},
		},
		{
			input: []MetadataPolicyOperator{
				Essential{}, Default{}, &Value{}, OneOf{}, SubsetOf{}, Add{}, SupersetOf{},
			},
			expected: []MetadataPolicyOperator{
				&Value{}, Add{}, Default{}, OneOf{}, SubsetOf{}, SupersetOf{}, Essential{},
			},
		},
		{
			input: []MetadataPolicyOperator{
				OneOf{}, SubsetOf{}, Add{}, SupersetOf{},
			},
			expected: []MetadataPolicyOperator{
				Add{}, OneOf{}, SubsetOf{}, SupersetOf{},
			},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := sortByPriority(tt.input)
			if !slices.EqualFunc(tt.expected, result, func(v1 MetadataPolicyOperator, v2 MetadataPolicyOperator) bool {
				return v1.String() == v2.String()
			}) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func Test_applyPolicy(t *testing.T) {
	tests := map[string]struct {
		subject func(t *testing.T) EntityStatement
		policy  func(t *testing.T) MetadataPolicy
		verify  func(t *testing.T, result *EntityStatement, err error)
	}{
		"we can resolve policy for a given chain": {
			subject: func(t *testing.T) EntityStatement {
				metadata := fmt.Sprintf(`{
  "authority_hints": [
    "https://umu.se"
  ],
  "exp": %d,
  "iat": 1568310847,
  "iss": "https://op.umu.se",
  "sub": "https://op.umu.se",
  "jwks": {
    "keys": [
      {
        "e": "AQAB",
        "kid": "dEEtRjlzY3djcENuT01wOGxrZlkxb3RIQVJlMTY0...",
        "kty": "RSA",
        "n": "x97YKqc9Cs-DNtFrQ7_vhXoH9bwkDWW6En2jJ044yH..."
      }
    ]
  },
  "metadata": {
    "openid_provider": {
      "issuer": "https://op.umu.se/openid",
      "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
      "authorization_endpoint":
      "https://op.umu.se/openid/authorization",
      "client_registration_types_supported": [
        "automatic",
        "explicit"
      ],
      "request_parameter_supported": true,
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ],
      "id_token_signing_alg_values_supported": [
        "ES256", "RS256"
      ],
      "logo_uri":
      "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
      "op_policy_uri":
      "https://www.umu.se/en/website/legal-information/",
      "response_types_supported": [
        "code",
        "code id_token",
        "token"
      ],
      "subject_types_supported": [
        "pairwise",
        "public"
      ],
      "token_endpoint": "https://op.umu.se/openid/token",
      "federation_registration_endpoint":
      "https://op.umu.se/openid/fedreg",
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
      ]
    }
  }
}`, time.Now().UTC().Unix())
				var result EntityStatement
				err := json.Unmarshal([]byte(metadata), &result)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return result
			},
			policy: func(t *testing.T) MetadataPolicy {
				policyAJson := `{"openid_provider": {"contacts": {"add": ["ops@edugain.geant.org"]}},"openid_relying_party": {"contacts": {"add": ["ops@edugain.geant.org"]}}}`
				policyBJson := `{"openid_provider": {"id_token_signing_alg_values_supported": {"subset_of": ["RS256","ES256","ES384","ES512"]},"token_endpoint_auth_methods_supported": {"subset_of": ["client_secret_jwt","private_key_jwt"]},"userinfo_signing_alg_values_supported": {"subset_of": ["ES256","ES384","ES512"]}}}`
				policyCJson := `{"openid_provider": {"contacts": {"add": ["ops@swamid.se"]},"organization_name": {"value": "University of Umeå"},"subject_types_supported": {"value": ["pairwise"]},"token_endpoint_auth_methods_supported": {"default": ["private_key_jwt"],"subset_of": ["private_key_jwt","client_secret_jwt"],"superset_of": ["private_key_jwt"]}}}`
				var policyA MetadataPolicy
				var policyB MetadataPolicy
				var policyC MetadataPolicy
				err := json.Unmarshal([]byte(policyAJson), &policyA)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				err = json.Unmarshal([]byte(policyBJson), &policyB)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				err = json.Unmarshal([]byte(policyCJson), &policyC)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				es, err := ProcessAndExtractPolicy([]EntityStatement{{}, {MetadataPolicy: &policyC}, {MetadataPolicy: &policyB}, {MetadataPolicy: &policyA}, {}})
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return *es
			},
			verify: func(t *testing.T, result *EntityStatement, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}

				expectedMetadata := `{
				  "authorization_endpoint": "https://op.umu.se/openid/authorization",
				  "contacts": [
					"ops@swamid.se",
					"ops@edugain.geant.org"
				  ],
				  "federation_registration_endpoint": "https://op.umu.se/openid/fedreg",
				  "client_registration_types_supported": [
					"automatic",
					"explicit"
				  ],
				  "grant_types_supported": [
					"authorization_code",
					"implicit",
					"urn:ietf:params:oauth:grant-type:jwt-bearer"
				  ],
				  "id_token_signing_alg_values_supported": [
					"RS256",
					"ES256"
				  ],
				  "issuer": "https://op.umu.se/openid",
				  "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
				  "logo_uri": "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
				  "organization_name": "University of Umeå",
				  "op_policy_uri": "https://www.umu.se/en/website/legal-information/",
				  "request_parameter_supported": true,
				  "response_types_supported": [
					"code",
					"code id_token",
					"token"
				  ],
				  "subject_types_supported": [
					"pairwise"
				  ],
				  "token_endpoint": "https://op.umu.se/openid/token",
				  "token_endpoint_auth_methods_supported": [
					"private_key_jwt",
					"client_secret_jwt"
				  ]
				}`

				var expected map[string]any
				err = json.Unmarshal([]byte(expectedMetadata), &expected)
				if err != nil {
					t.Fatalf("expected valid JSON in expected metadata, got error %q", err.Error())
				}

				if result.Metadata.OpenIDConnectOpenIDProviderMetadata == nil {
					t.Fatalf("expected openid_provider metadata, but it does not exist")
				}

				resultBytes, err := json.Marshal(*result.Metadata.OpenIDConnectOpenIDProviderMetadata)
				if err != nil {
					t.Fatalf("error marshalling result to json: %q", err.Error())
				}

				var resultMap map[string]any
				err = json.Unmarshal(resultBytes, &resultMap)
				if err != nil {
					t.Fatalf("expected valid JSON in result metadata, got error %q", err.Error())
				}

				if diff := cmp.Diff(expected, resultMap, cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
		"we can resolve policy for a given chain that omits the trailing trust anchor entity configuration": {
			subject: func(t *testing.T) EntityStatement {
				metadata := fmt.Sprintf(`{
  "authority_hints": [
    "https://umu.se"
  ],
  "exp": %d,
  "iat": 1568310847,
  "iss": "https://op.umu.se",
  "sub": "https://op.umu.se",
  "jwks": {
    "keys": [
      {
        "e": "AQAB",
        "kid": "dEEtRjlzY3djcENuT01wOGxrZlkxb3RIQVJlMTY0...",
        "kty": "RSA",
        "n": "x97YKqc9Cs-DNtFrQ7_vhXoH9bwkDWW6En2jJ044yH..."
      }
    ]
  },
  "metadata": {
    "openid_provider": {
      "issuer": "https://op.umu.se/openid",
      "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
      "authorization_endpoint":
      "https://op.umu.se/openid/authorization",
      "client_registration_types_supported": [
        "automatic",
        "explicit"
      ],
      "request_parameter_supported": true,
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ],
      "id_token_signing_alg_values_supported": [
        "ES256", "RS256"
      ],
      "logo_uri":
      "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
      "op_policy_uri":
      "https://www.umu.se/en/website/legal-information/",
      "response_types_supported": [
        "code",
        "code id_token",
        "token"
      ],
      "subject_types_supported": [
        "pairwise",
        "public"
      ],
      "token_endpoint": "https://op.umu.se/openid/token",
      "federation_registration_endpoint":
      "https://op.umu.se/openid/fedreg",
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
      ]
    }
  }
}`, time.Now().UTC().Unix())
				var result EntityStatement
				err := json.Unmarshal([]byte(metadata), &result)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return result
			},
			policy: func(t *testing.T) MetadataPolicy {
				policyAJson := `{"openid_provider": {"contacts": {"add": ["ops@edugain.geant.org"]}},"openid_relying_party": {"contacts": {"add": ["ops@edugain.geant.org"]}}}`
				policyBJson := `{"openid_provider": {"id_token_signing_alg_values_supported": {"subset_of": ["RS256","ES256","ES384","ES512"]},"token_endpoint_auth_methods_supported": {"subset_of": ["client_secret_jwt","private_key_jwt"]},"userinfo_signing_alg_values_supported": {"subset_of": ["ES256","ES384","ES512"]}}}`
				policyCJson := `{"openid_provider": {"contacts": {"add": ["ops@swamid.se"]},"organization_name": {"value": "University of Umeå"},"subject_types_supported": {"value": ["pairwise"]},"token_endpoint_auth_methods_supported": {"default": ["private_key_jwt"],"subset_of": ["private_key_jwt","client_secret_jwt"],"superset_of": ["private_key_jwt"]}}}`
				var policyA MetadataPolicy
				var policyB MetadataPolicy
				var policyC MetadataPolicy
				err := json.Unmarshal([]byte(policyAJson), &policyA)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				err = json.Unmarshal([]byte(policyBJson), &policyB)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				err = json.Unmarshal([]byte(policyCJson), &policyC)
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				es, err := ProcessAndExtractPolicy([]EntityStatement{{}, {MetadataPolicy: &policyC}, {MetadataPolicy: &policyB}, {MetadataPolicy: &policyA}})
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return *es
			},
			verify: func(t *testing.T, result *EntityStatement, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}

				expectedMetadata := `{
				  "authorization_endpoint":
					"https://op.umu.se/openid/authorization",
				  "contacts": [
					"ops@swamid.se",
					"ops@edugain.geant.org"
				  ],
				  "federation_registration_endpoint":
					"https://op.umu.se/openid/fedreg",
				  "client_registration_types_supported": [
					"automatic",
					"explicit"
				  ],
				  "grant_types_supported": [
					"authorization_code",
					"implicit",
					"urn:ietf:params:oauth:grant-type:jwt-bearer"
				  ],
				  "id_token_signing_alg_values_supported": [
					"RS256",
					"ES256"
				  ],
				  "issuer": "https://op.umu.se/openid",
				  "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
				  "logo_uri":
					"https://www.umu.se/img/umu-logo-left-neg-SE.svg",
				  "organization_name": "University of Umeå",
				  "op_policy_uri":
					"https://www.umu.se/en/website/legal-information/",
				  "request_parameter_supported": true,
				  "response_types_supported": [
					"code",
					"code id_token",
					"token"
				  ],
				  "subject_types_supported": [
					"pairwise"
				  ],
				  "token_endpoint": "https://op.umu.se/openid/token",
				  "token_endpoint_auth_methods_supported": [
					"private_key_jwt",
					"client_secret_jwt"
				  ]
				}`

				var expected map[string]any
				err = json.Unmarshal([]byte(expectedMetadata), &expected)
				if err != nil {
					t.Fatalf("expected valid JSON in expected metadata, got error %q", err.Error())
				}

				if result.Metadata.OpenIDConnectOpenIDProviderMetadata == nil {
					t.Fatalf("expected openid_provider metadata, but it does not exist")
				}

				resultBytes, err := json.Marshal(*result.Metadata.OpenIDConnectOpenIDProviderMetadata)
				if err != nil {
					t.Fatalf("error marshalling result to json: %q", err.Error())
				}

				var resultMap map[string]any
				err = json.Unmarshal(resultBytes, &resultMap)
				if err != nil {
					t.Fatalf("expected valid JSON in result metadata, got error %q", err.Error())
				}

				if diff := cmp.Diff(expected, resultMap, cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
		"we correctly handle the scope edge case when applying an array to existing values": {
			subject: func(t *testing.T) EntityStatement {
				return EntityStatement{
					Metadata: &Metadata{
						OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
							"client_id": "https://op.umu.se/openid",
							"scope":     "openid",
						},
					},
				}
			},
			policy: func(t *testing.T) MetadataPolicy {
				addOperator, err := NewAdd([]any{"foo", "bar", "baz"})
				if err != nil {
					t.Fatalf("expected no error creating add operator, got %q", err.Error())
				}
				policyA := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{addOperator}}}}
				es, err := ProcessAndExtractPolicy([]EntityStatement{{}, {MetadataPolicy: &policyA}})
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return *es
			},
			verify: func(t *testing.T, result *EntityStatement, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}

				expected := map[string]any{
					"client_id": "https://op.umu.se/openid",
					"scope":     "openid foo bar baz",
				}

				if diff := cmp.Diff(expected, (map[string]any)(*result.Metadata.OpenIDRelyingPartyMetadata), cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
		"we correctly handle the scope edge case when applying an array to no existing values": {
			subject: func(t *testing.T) EntityStatement {
				return EntityStatement{
					Metadata: &Metadata{
						OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
							"client_id": "https://op.umu.se/openid",
						},
					},
				}
			},
			policy: func(t *testing.T) MetadataPolicy {
				addOperator, err := NewAdd([]any{"foo", "bar", "baz"})
				if err != nil {
					t.Fatalf("expected no error creating add operator, got %q", err.Error())
				}
				policyA := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{addOperator}}}}
				es, err := ProcessAndExtractPolicy([]EntityStatement{{}, {MetadataPolicy: &policyA}})
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return *es
			},
			verify: func(t *testing.T, result *EntityStatement, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}

				expected := map[string]any{
					"client_id": "https://op.umu.se/openid",
					"scope":     "foo bar baz",
				}

				if diff := cmp.Diff(expected, (map[string]any)(*result.Metadata.OpenIDRelyingPartyMetadata), cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
		"we correctly handle the scope edge case when applying an array to no existing values with a mix of metadata policies": {
			subject: func(t *testing.T) EntityStatement {
				return EntityStatement{
					Metadata: &Metadata{
						OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
							"client_id": "https://op.umu.se/openid",
						},
					},
				}
			},
			policy: func(t *testing.T) MetadataPolicy {
				valueOperator, err := NewValue("foo bar baz bong")
				if err != nil {
					t.Fatalf("expected no error creating value operator, got %q", err.Error())
				}
				valueOperator2, err := NewValue([]any{"foo", "bar", "baz", "bong"})
				if err != nil {
					t.Fatalf("expected no error creating value operator, got %q", err.Error())
				}
				addOperator, err := NewAdd([]any{"foo", "bar", "baz"})
				if err != nil {
					t.Fatalf("expected no error creating add operator, got %q", err.Error())
				}
				policyA := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{valueOperator}}}}
				policyB := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{valueOperator2}}}}
				policyC := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{addOperator}}}}
				es, err := ProcessAndExtractPolicy([]EntityStatement{{}, {MetadataPolicy: &policyC}, {MetadataPolicy: &policyB}, {MetadataPolicy: &policyA}})
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				return *es
			},
			verify: func(t *testing.T, result *EntityStatement, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}

				expected := map[string]any{
					"client_id": "https://op.umu.se/openid",
					"scope":     "foo bar baz bong",
				}

				if diff := cmp.Diff(expected, (map[string]any)(*result.Metadata.OpenIDRelyingPartyMetadata), cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := ApplyPolicy(tt.subject(t), tt.policy(t))
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			tt.verify(t, result, err)
		})
	}
}

func TestReMarshalJsonAsEntityMetadata(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	tests := map[string]struct {
		data     any
		validate func(t *testing.T, result *TestStruct, err error)
	}{
		"marshals and unmarshals valid struct": {
			data: map[string]any{
				"name":  "test",
				"value": 123,
			},
			validate: func(t *testing.T, result *TestStruct, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.Name != "test" {
					t.Errorf("expected name 'test', got %q", result.Name)
				}
				if result.Value != 123 {
					t.Errorf("expected value 123, got %d", result.Value)
				}
			},
		},
		"handles empty object": {
			data: map[string]any{},
			validate: func(t *testing.T, result *TestStruct, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.Name != "" {
					t.Errorf("expected empty name, got %q", result.Name)
				}
				if result.Value != 0 {
					t.Errorf("expected value 0, got %d", result.Value)
				}
			},
		},
		"returns error for invalid data type": {
			data: "test",
			validate: func(t *testing.T, result *TestStruct, err error) {
				if err == nil {
					t.Fatal("expected error for string data, got nil")
				}
			},
		},
		"handles nested structures": {
			data: map[string]any{
				"name":  "nested",
				"value": 456,
			},
			validate: func(t *testing.T, result *TestStruct, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result.Name != "nested" {
					t.Errorf("expected name 'nested', got %q", result.Name)
				}
				if result.Value != 456 {
					t.Errorf("expected value 456, got %d", result.Value)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := ReMarshalJsonAsEntityMetadata[TestStruct](tt.data)
			tt.validate(t, result, err)
		})
	}
}

func TestVerifyFederationEndpoint(t *testing.T) {
	tests := map[string]struct {
		endpoint any
		validate func(t *testing.T, err error)
	}{
		"valid https endpoint": {
			endpoint: "https://example.com/endpoint",
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid https endpoint, got %q", err.Error())
				}
			},
		},
		"valid https endpoint with port": {
			endpoint: "https://example.com:8443/endpoint",
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid https endpoint with port, got %q", err.Error())
				}
			},
		},
		"valid https endpoint with query parameters": {
			endpoint: "https://example.com/endpoint?param=value",
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid https endpoint with query params, got %q", err.Error())
				}
			},
		},
		"valid https endpoint with path": {
			endpoint: "https://example.com/path/to/endpoint",
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid https endpoint with path, got %q", err.Error())
				}
			},
		},
		"nil endpoint is valid": {
			endpoint: nil,
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for nil endpoint, got %q", err.Error())
				}
			},
		},
		"invalid endpoint - not a string": {
			endpoint: 123,
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for non-string endpoint, got nil")
				}
			},
		},
		"invalid endpoint - http scheme": {
			endpoint: "http://example.com/endpoint",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for http scheme, got nil")
				}
			},
		},
		"invalid endpoint - contains fragment": {
			endpoint: "https://example.com/endpoint#fragment",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for endpoint with fragment, got nil")
				}
			},
		},
		"invalid endpoint - malformed URL": {
			endpoint: "not a valid url",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for malformed URL, got nil")
				}
			},
		},
		"invalid endpoint - ftp scheme": {
			endpoint: "ftp://example.com/endpoint",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for ftp scheme, got nil")
				}
			},
		},
		"invalid endpoint - empty string": {
			endpoint: "",
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for empty string endpoint, got nil")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifyFederationEndpoint(tt.endpoint)
			tt.validate(t, err)
		})
	}
}

func TestConvertStringsToAnySlice(t *testing.T) {
	tests := map[string]struct {
		input    []string
		validate func(t *testing.T, result []any)
	}{
		"converts empty slice": {
			input: []string{},
			validate: func(t *testing.T, result []any) {
				if len(result) != 0 {
					t.Errorf("expected empty slice, got length %d", len(result))
				}
			},
		},
		"converts single element": {
			input: []string{"foo"},
			validate: func(t *testing.T, result []any) {
				if len(result) != 1 {
					t.Fatalf("expected slice of length 1, got %d", len(result))
				}
				if result[0] != "foo" {
					t.Errorf("expected 'foo', got %v", result[0])
				}
			},
		},
		"converts multiple elements": {
			input: []string{"foo", "bar", "baz"},
			validate: func(t *testing.T, result []any) {
				if len(result) != 3 {
					t.Fatalf("expected slice of length 3, got %d", len(result))
				}
				expected := []string{"foo", "bar", "baz"}
				for i, exp := range expected {
					if result[i] != exp {
						t.Errorf("expected %q at index %d, got %v", exp, i, result[i])
					}
				}
			},
		},
		"converts strings with special characters": {
			input: []string{"hello world", "test@example.com", "path/to/resource"},
			validate: func(t *testing.T, result []any) {
				if len(result) != 3 {
					t.Fatalf("expected slice of length 3, got %d", len(result))
				}
				expected := []string{"hello world", "test@example.com", "path/to/resource"}
				for i, exp := range expected {
					if result[i] != exp {
						t.Errorf("expected %q at index %d, got %v", exp, i, result[i])
					}
				}
			},
		},
		"converts strings with unicode": {
			input: []string{"こんにちは", "emoji:😀", "special:™"},
			validate: func(t *testing.T, result []any) {
				if len(result) != 3 {
					t.Fatalf("expected slice of length 3, got %d", len(result))
				}
				expected := []string{"こんにちは", "emoji:😀", "special:™"}
				for i, exp := range expected {
					if result[i] != exp {
						t.Errorf("expected %q at index %d, got %v", exp, i, result[i])
					}
				}
			},
		},
		"converts empty strings": {
			input: []string{"", "", ""},
			validate: func(t *testing.T, result []any) {
				if len(result) != 3 {
					t.Fatalf("expected slice of length 3, got %d", len(result))
				}
				for i, v := range result {
					if v != "" {
						t.Errorf("expected empty string at index %d, got %v", i, v)
					}
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := ConvertStringsToAnySlice(tt.input)
			tt.validate(t, result)
		})
	}
}

func TestCalculateChainExpiration(t *testing.T) {
	now := time.Now().UTC().Unix()
	future1 := now + 3600  // 1 hour from now
	future2 := now + 7200  // 2 hours from now
	future3 := now + 10800 // 3 hours from now

	tests := map[string]struct {
		chain    []EntityStatement
		validate func(t *testing.T, result int64)
	}{
		"returns expiration from single statement chain": {
			chain: []EntityStatement{
				{Exp: future1},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected expiration %d, got %d", future1, result)
				}
			},
		},
		"returns minimum expiration from chain with multiple statements": {
			chain: []EntityStatement{
				{Exp: future3},
				{Exp: future1},
				{Exp: future2},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
		"returns minimum when first statement has minimum": {
			chain: []EntityStatement{
				{Exp: future1},
				{Exp: future2},
				{Exp: future3},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
		"returns minimum when last statement has minimum": {
			chain: []EntityStatement{
				{Exp: future3},
				{Exp: future2},
				{Exp: future1},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
		"handles chain with same expiration": {
			chain: []EntityStatement{
				{Exp: future2},
				{Exp: future2},
				{Exp: future2},
			},
			validate: func(t *testing.T, result int64) {
				if result != future2 {
					t.Errorf("expected expiration %d, got %d", future2, result)
				}
			},
		},
		"handles chain with expired statements": {
			chain: []EntityStatement{
				{Exp: now - 3600}, // Expired 1 hour ago
				{Exp: future1},
				{Exp: future2},
			},
			validate: func(t *testing.T, result int64) {
				if result != now-3600 {
					t.Errorf("expected minimum expiration %d, got %d", now-3600, result)
				}
			},
		},
		"handles chain with two statements": {
			chain: []EntityStatement{
				{Exp: future2},
				{Exp: future1},
			},
			validate: func(t *testing.T, result int64) {
				if result != future1 {
					t.Errorf("expected minimum expiration %d, got %d", future1, result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := CalculateChainExpiration(tt.chain)
			tt.validate(t, result)
		})
	}
}

func TestApplyPolicyMergesNewPolicies(t *testing.T) {
	existingValueOp, _ := NewValue("existing-value")
	existing := map[string]PolicyOperators{
		"existing_claim": {
			Metadata: []MetadataPolicyOperator{existingValueOp},
		},
	}

	newValueOp, _ := NewValue("new-value")
	newAddOp, _ := NewAdd([]string{"scope1", "scope2"})
	policy := map[string]PolicyOperators{
		"new_claim": {
			Metadata: []MetadataPolicyOperator{newValueOp},
		},
		"another_new_claim": {
			Metadata: []MetadataPolicyOperator{newAddOp},
		},
	}

	result, err := applyPolicy(existing, policy)
	if err != nil {
		t.Fatalf("applyPolicy failed: %v", err)
	}

	if _, ok := result["existing_claim"]; !ok {
		t.Error("existing_claim should still be present")
	}

	if _, ok := result["new_claim"]; !ok {
		t.Error("new_claim should be added from policy")
	}

	if _, ok := result["another_new_claim"]; !ok {
		t.Error("another_new_claim should be added from policy")
	}

	if len(result) != 3 {
		t.Errorf("expected 3 claims in result, got %d", len(result))
	}
}

func TestApplyPolicyMergesExistingAndNewPolicies(t *testing.T) {
	existingValueOp, _ := NewValue([]string{"val1", "val2"})
	existing := map[string]PolicyOperators{
		"claim_a": {
			Metadata: []MetadataPolicyOperator{existingValueOp},
		},
	}

	policyValueOp, _ := NewValue([]string{"val1", "val2"})
	policyAddOp, _ := NewAdd([]string{"new1", "new2"})
	policy := map[string]PolicyOperators{
		"claim_a": {
			Metadata: []MetadataPolicyOperator{policyValueOp},
		},
		"claim_b": {
			Metadata: []MetadataPolicyOperator{policyAddOp},
		},
	}

	result, err := applyPolicy(existing, policy)
	if err != nil {
		t.Fatalf("applyPolicy failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 claims in result, got %d", len(result))
	}

	if _, ok := result["claim_a"]; !ok {
		t.Error("claim_a should be present")
	}

	if _, ok := result["claim_b"]; !ok {
		t.Error("claim_b should be present (added from policy)")
	}
}

func TestApplyPolicyWithNilExisting(t *testing.T) {
	valueOp, _ := NewValue("test-value")
	addOp, _ := NewAdd([]string{"a", "b"})

	policy := map[string]PolicyOperators{
		"claim1": {
			Metadata: []MetadataPolicyOperator{valueOp},
		},
		"claim2": {
			Metadata: []MetadataPolicyOperator{addOp},
		},
	}

	result, err := applyPolicy(nil, policy)
	if err != nil {
		t.Fatalf("applyPolicy failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 claims in result, got %d", len(result))
	}

	if !reflect.DeepEqual(result, policy) {
		t.Error("result should equal policy when existing is nil")
	}
}

func TestProcessAndExtractPolicyMergesAllLevels(t *testing.T) {
	leaf := EntityStatement{
		Sub: EntityIdentifier("https://leaf.example.com"),
		Iss: EntityIdentifier("https://leaf.example.com"),
	}

	intermediateAddOp, _ := NewAdd([]string{"scope1"})
	intermediate := EntityStatement{
		Sub: EntityIdentifier("https://leaf.example.com"),
		Iss: EntityIdentifier("https://intermediate.example.com"),
		MetadataPolicy: &MetadataPolicy{
			OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
				"scope": {
					Metadata: []MetadataPolicyOperator{intermediateAddOp},
				},
			},
		},
	}

	taValueOp, _ := NewValue("required_value")
	taAddOp, _ := NewAdd([]string{"scope2"})
	trustAnchor := EntityStatement{
		Sub: EntityIdentifier("https://intermediate.example.com"),
		Iss: EntityIdentifier("https://trust-anchor.example.com"),
		MetadataPolicy: &MetadataPolicy{
			OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
				"client_name": {
					Metadata: []MetadataPolicyOperator{taValueOp},
				},
				"scope": {
					Metadata: []MetadataPolicyOperator{taAddOp},
				},
			},
		},
	}

	trustChain := []EntityStatement{leaf, intermediate, trustAnchor}

	result, err := ProcessAndExtractPolicy(trustChain)
	if err != nil {
		t.Fatalf("ProcessAndExtractPolicy failed: %v", err)
	}

	if result == nil {
		t.Fatal("result should not be nil")
	}

	if result.OpenIDRelyingPartyMetadata == nil {
		t.Fatal("OpenIDRelyingPartyMetadata should not be nil")
	}

	if _, ok := result.OpenIDRelyingPartyMetadata["scope"]; !ok {
		t.Error("scope policy should be present")
	}

	if _, ok := result.OpenIDRelyingPartyMetadata["client_name"]; !ok {
		t.Error("client_name policy from trust anchor should be present")
	}

	if len(result.OpenIDRelyingPartyMetadata) != 2 {
		t.Errorf("expected 2 policies in OpenIDRelyingPartyMetadata, got %d", len(result.OpenIDRelyingPartyMetadata))
	}
}
