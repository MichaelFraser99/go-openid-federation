package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplyPolicy_ScopeOperandTypes(t *testing.T) {
	leaf := func() EntityStatement {
		return EntityStatement{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
			"redirect_uris": []any{"https://leaf.example.com/cb"},
		}}}
	}

	tests := []struct {
		name        string
		reference   string
		policy      string
		expectErr   string
		expectScope string
	}{
		{
			name:        "a space separated string value is split into tokens",
			reference:   "6.1.3.1.8",
			policy:      `{"openid_relying_party":{"scope":{"value":"openid address"}}}`,
			expectScope: "openid address",
		},
		{
			name:        "an array of strings is kept",
			reference:   "6.1.3.1.8",
			policy:      `{"openid_relying_party":{"scope":{"value":["openid","address"]}}}`,
			expectScope: "openid address",
		},
		{
			name:        "a space separated default is split into tokens",
			reference:   "6.1.3.1.8",
			policy:      `{"openid_relying_party":{"scope":{"default":"openid profile"}}}`,
			expectScope: "openid profile",
		},
		{
			name:      "a numeric value is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":5}}}`,
			expectErr: "scope",
		},
		{
			name:      "a boolean value is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":true}}}`,
			expectErr: "scope",
		},
		{
			name:      "an object value is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":{"a":1}}}}`,
			expectErr: "scope",
		},
		{
			name:      "a numeric default is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"default":5}}}`,
			expectErr: "scope",
		},
		{
			name:      "an array containing a number is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":["openid",5]}}}`,
			expectErr: "scope",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("[%s] the policy fixture did not parse: %v", tc.reference, err)
			}

			var result *EntityStatement
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[%s] a scope operand panicked, which section 6.1.3 requires to be a policy error: %v", tc.reference, r)
					}
				}()
				result, err = ApplyPolicy(leaf(), policy)
			}()

			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("[%s] expected a policy error naming %q, got an applied policy", tc.reference, tc.expectErr)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected a policy error naming %q, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the policy to apply, got %v", tc.reference, err)
			}

			got := (*result.Metadata.OpenIDRelyingPartyMetadata)["scope"]
			if got != tc.expectScope {
				t.Errorf("[%s] expected scope %q, got %v", tc.reference, tc.expectScope, got)
			}
		})
	}
}

func TestMergePolicyOperators_ScopeOperandTypesDoNotPanic(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{name: "numeric defaults", first: `{"default":5}`, second: `{"default":5}`},
		{name: "numeric values", first: `{"value":5}`, second: `{"value":5}`},
		{name: "object values", first: `{"value":{"a":1}}`, second: `{"value":{"a":1}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var first, second PolicyOperators
			if err := json.Unmarshal([]byte(tc.first), &first); err != nil {
				t.Fatalf("the first fixture did not parse: %v", err)
			}
			if err := json.Unmarshal([]byte(tc.second), &second); err != nil {
				t.Fatalf("the second fixture did not parse: %v", err)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("merging a non-string scope operand panicked: %v", r)
				}
			}()
			if _, err := MergePolicyOperators("scope", first, second); err != nil {
				t.Logf("merge reported a policy error, which is acceptable: %v", err)
			}
		})
	}
}
