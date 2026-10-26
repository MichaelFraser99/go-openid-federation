package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func policyStatement(t *testing.T, policy string) EntityStatement {
	t.Helper()
	var statement EntityStatement
	raw := `{"iss":"https://ta.example.com","sub":"https://leaf.example.com","iat":1,"exp":99999999999,"jwks":{"keys":[]},"metadata_policy":{"oauth_client":` + policy + `}}`
	if err := json.Unmarshal([]byte(raw), &statement); err != nil {
		t.Fatalf("failed to parse the fixture policy: %v", err)
	}
	return statement
}

func clientSubject(t *testing.T, metadata string) EntityStatement {
	t.Helper()
	var statement EntityStatement
	raw := `{"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":1,"exp":99999999999,"jwks":{"keys":[]},"metadata":{"oauth_client":{"redirect_uris":["https://leaf.example.com/cb"],` + metadata + `}}}`
	if err := json.Unmarshal([]byte(raw), &statement); err != nil {
		t.Fatalf("failed to parse the fixture subject: %v", err)
	}
	return statement
}

func TestMerge_ReturnsAValueTypeForEveryOperator(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		operator  MetadataPolicyOperator
		operand   any
	}{
		{name: "value", reference: "6.1.3.1.1", operator: Value{operatorValue: []any{"a"}}, operand: []any{"a"}},
		{name: "add", reference: "6.1.3.1.2", operator: Add{operatorValue: []any{"a"}}, operand: []any{"b"}},
		{name: "default", reference: "6.1.3.1.3", operator: Default{operatorValue: []any{"a"}}, operand: []any{"a"}},
		{name: "one_of", reference: "6.1.3.1.4", operator: OneOf{operatorValue: []any{"a", "b"}}, operand: []any{"a"}},
		{name: "subset_of", reference: "6.1.3.1.5", operator: SubsetOf{operatorValue: []any{"a", "b"}}, operand: []any{"a"}},
		{name: "superset_of", reference: "6.1.3.1.6", operator: SupersetOf{operatorValue: []any{"a"}}, operand: []any{"b"}},
		{name: "essential", reference: "6.1.3.1.7", operator: Essential{operatorValue: true}, operand: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := tc.operator.Merge(tc.operand)
			if err != nil {
				t.Fatalf("[%s] expected the operands to merge, got %v", tc.reference, err)
			}
			if reflect.TypeOf(merged).Kind() == reflect.Pointer {
				t.Errorf("[%s] a merged operator must keep the receiver shape, or a lookup for it in metadataPolicySetContains misses it and the rule between the two operators is never checked, got %T", tc.reference, merged)
			}
			if _, found := metadataPolicySetContains([]MetadataPolicyOperator{merged}, reflect.TypeOf(tc.operator)); !found {
				t.Errorf("[%s] a merged operator must still be found by a lookup for its own type, got %T", tc.reference, merged)
			}
		})
	}
}

func TestProcessAndExtractPolicy_ARuleIsCheckedWhenBothStatementsCarryBothOperators(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		subject   string
		authority string
		superior  string
	}{
		{
			name:      "an add that is not a subset of the merged subset_of",
			reference: "6.1.3.1.2",
			subject:   `"acr_values":["a","b","c"]`,
			authority: `{"acr_values":{"add":["b"],"subset_of":["b","c"]}}`,
			superior:  `{"acr_values":{"add":["a"],"subset_of":["a","b"]}}`,
		},
		{
			name:      "a subset_of that is not a superset of the merged superset_of",
			reference: "6.1.3.1.6",
			subject:   `"acr_values":["a","b","c"]`,
			authority: `{"acr_values":{"subset_of":["a","b"],"superset_of":["a"]}}`,
			superior:  `{"acr_values":{"subset_of":["b","c"],"superset_of":["c"]}}`,
		},
		{
			name:      "an add that is not a subset of the merged subset_of on scope",
			reference: "6.1.3.1.8",
			subject:   `"scope":"openid profile admin"`,
			authority: `{"scope":{"add":["admin"],"subset_of":["openid","admin"]}}`,
			superior:  `{"scope":{"add":["openid"],"subset_of":["openid","profile"]}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := clientSubject(t, tc.subject)

			merged, err := ProcessAndExtractPolicy([]EntityStatement{
				leaf,
				policyStatement(t, tc.authority),
				policyStatement(t, tc.superior),
			})
			if err != nil {
				return
			}

			applied, applyErr := ApplyPolicy(leaf, *merged)
			if applyErr != nil {
				t.Fatalf("[%s] operators the spec does not permit together are a fault in the policy, so the chain must be refused when the policy is processed rather than when it is applied to a subject, got %v", tc.reference, applyErr)
			}
			t.Errorf("[%s] a rule the spec requires between two operators must be checked even when both statements carry both of them, got the resolved metadata %v", tc.reference, *applied.Metadata.OAuthClientMetadata)
		})
	}
}

func TestMetadataPolicySetContains_FindsAnOperatorWhateverShapeHoldsIt(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		set       []MetadataPolicyOperator
		lookFor   reflect.Type
	}{
		{name: "a value held by value", reference: "6.1.3.1.1", set: []MetadataPolicyOperator{Value{operatorValue: []any{"a"}}}, lookFor: reflect.TypeOf(Value{})},
		{name: "a value held by pointer", reference: "6.1.3.1.1", set: []MetadataPolicyOperator{&Value{operatorValue: []any{"a"}}}, lookFor: reflect.TypeOf(Value{})},
		{name: "an add held by pointer", reference: "6.1.3.1.2", set: []MetadataPolicyOperator{&Add{operatorValue: []any{"a"}}}, lookFor: reflect.TypeOf(Add{})},
		{name: "a subset_of held by pointer", reference: "6.1.3.1.5", set: []MetadataPolicyOperator{&SubsetOf{operatorValue: []any{"a"}}}, lookFor: reflect.TypeOf(SubsetOf{})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found, ok := metadataPolicySetContains(tc.set, tc.lookFor)
			if !ok {
				t.Fatalf("[%s] an operator must be found by a lookup for its type whatever shape holds it, or the rule between it and its partner is never checked", tc.reference)
			}
			if reflect.TypeOf(found) != tc.lookFor {
				t.Errorf("[%s] the operator handed back must be the value type the caller asserts on, got %T", tc.reference, found)
			}
		})
	}
}

func TestValidatePoliciesCanCombine_RefusesAForbiddenPairHeldByPointer(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		policies  []MetadataPolicyOperator
	}{
		{
			name:      "an add that is not a subset of subset_of, both held by pointer",
			reference: "6.1.3.1.2",
			policies:  []MetadataPolicyOperator{&Add{operatorValue: []any{"a"}}, &SubsetOf{operatorValue: []any{"b"}}},
		},
		{
			name:      "an add that is not a subset of subset_of, add held by pointer",
			reference: "6.1.3.1.2",
			policies:  []MetadataPolicyOperator{&Add{operatorValue: []any{"a"}}, SubsetOf{operatorValue: []any{"b"}}},
		},
		{
			name:      "an add that is not a subset of subset_of, both held by value",
			reference: "6.1.3.1.2",
			policies:  []MetadataPolicyOperator{Add{operatorValue: []any{"a"}}, SubsetOf{operatorValue: []any{"b"}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePoliciesCanCombine(tc.policies); err == nil {
				t.Errorf("[%s] add must be a subset of subset_of, so this pair must be refused whatever shape holds the operators", tc.reference)
			}
		})
	}
}
