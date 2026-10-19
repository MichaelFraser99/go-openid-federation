package model

import (
	"encoding/json"
	"fmt"
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
			expectErr: "all scope values must be strings",
		},
		{
			name:      "a boolean value is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":true}}}`,
			expectErr: "all scope values must be strings",
		},
		{
			name:      "an object value is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":{"a":1}}}}`,
			expectErr: "all scope values must be strings",
		},
		{
			name:      "a numeric default is a policy error",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"default":5}}}`,
			expectErr: "all scope values must be strings",
		},
		{
			name:      "an array containing a number is a policy error",
			reference: "6.1.3 (already enforced before this change)",
			policy:    `{"openid_relying_party":{"scope":{"value":["openid",5]}}}`,
			expectErr: "all scope values must be strings",
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

func TestMergePolicyOperators_ScopeDefaultIsSplitIntoTokens(t *testing.T) {
	var first, second PolicyOperators
	if err := json.Unmarshal([]byte(`{"default":"openid profile"}`), &first); err != nil {
		t.Fatalf("the first fixture did not parse: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"default":"openid profile"}`), &second); err != nil {
		t.Fatalf("the second fixture did not parse: %v", err)
	}

	merged, err := MergePolicyOperators("scope", first, second)
	if err != nil {
		t.Fatalf("expected two equal space separated defaults to merge, got %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("expected one merged operator, got %d", len(merged))
	}

	value := merged[0].OperatorValue()
	tokens, ok := value.([]any)
	if !ok {
		t.Fatalf("expected the merged default to be a token slice so the two levels compare per token, got %T", value)
	}
	if len(tokens) != 2 || tokens[0] != "openid" || tokens[1] != "profile" {
		t.Errorf("expected the default to be split into its tokens, got %v", tokens)
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

func TestProcessAndExtractPolicy_ScopeOperandTypeIsCheckedWhateverTheMetadataHolds(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		policy    string
		expectErr string
	}{
		{
			name:      "a numeric default is refused even when the metadata already has a scope",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"default":5}}}`,
			expectErr: "all scope values must be strings",
		},
		{
			name:      "a numeric value is refused",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"value":5}}}`,
			expectErr: "all scope values must be strings",
		},
		{
			name:      "a numeric element inside subset_of is refused",
			reference: "6.1.3",
			policy:    `{"openid_relying_party":{"scope":{"subset_of":[5]}}}`,
			expectErr: "all scope values must be strings",
		},
		{
			name:      "essential is a boolean and is not a scope value",
			reference: "6.1.3.1.7",
			policy:    `{"openid_relying_party":{"scope":{"essential":true}}}`,
		},
		{
			name:      "a space separated string is accepted",
			reference: "6.1.3.1.8",
			policy:    `{"openid_relying_party":{"scope":{"value":"openid profile"}}}`,
		},
		{
			name:      "an array of strings is accepted",
			reference: "6.1.3.1.8",
			policy:    `{"openid_relying_party":{"scope":{"subset_of":["openid","profile"]}}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("[%s] the policy fixture did not parse: %v", tc.reference, err)
			}
			subordinate := EntityStatement{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &policy}

			_, err := ProcessAndExtractPolicy([]EntityStatement{{}, subordinate, {}})

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the policy to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] section 6.1.3 requires a policy error for an unsupported operand type, got an accepted policy", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestProcessAndExtractPolicy_BoundsConflictWork(t *testing.T) {
	operand := func(n int) string {
		values := make([]string, n)
		for i := range values {
			values[i] = fmt.Sprintf("%q", fmt.Sprintf("value-%d", i))
		}
		return "[" + strings.Join(values, ",") + "]"
	}

	tests := []struct {
		name      string
		policy    string
		expectErr string
	}{
		{
			name:   "a single large operand has no pair to compare against",
			policy: `{"openid_relying_party":{"contacts":{"subset_of":` + operand(4000) + `}}}`,
		},
		{
			name:   "two small operands are well inside the budget",
			policy: `{"openid_relying_party":{"contacts":{"subset_of":` + operand(50) + `,"superset_of":` + operand(50) + `}}}`,
		},
		{
			name:      "two large operands exceed the budget",
			policy:    `{"openid_relying_party":{"contacts":{"subset_of":` + operand(2000) + `,"superset_of":` + operand(2000) + `}}}`,
			expectErr: "operand comparisons",
		},
		{
			name:      "four medium operands exceed the budget together",
			policy:    `{"openid_relying_party":{"contacts":{"value":` + operand(700) + `,"add":` + operand(700) + `,"subset_of":` + operand(700) + `,"superset_of":` + operand(700) + `}}}`,
			expectErr: "operand comparisons",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("the policy fixture did not parse: %v", err)
			}
			subordinate := EntityStatement{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &policy}

			_, err := ProcessAndExtractPolicy([]EntityStatement{{}, subordinate, {}})

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("expected a policy within the budget to be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a policy beyond the budget to be refused")
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("expected an error naming the comparison budget, got %v", err)
			}
		})
	}
}
