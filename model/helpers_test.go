package model

import (
	"encoding/json"
	"fmt"
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
				addOperator, err := NewAdd([]any{"foo", "bar", "baz"})
				if err != nil {
					t.Fatalf("expected no error creating add operator, got %q", err.Error())
				}
				policyA := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{valueOperator}}}}
				policyB := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"scope": {[]MetadataPolicyOperator{addOperator}}}}
				es, err := ProcessAndExtractPolicy([]EntityStatement{{}, {MetadataPolicy: &policyB}, {MetadataPolicy: &policyA}})
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
