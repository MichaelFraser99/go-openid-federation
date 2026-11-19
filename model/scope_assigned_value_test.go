package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func scopeSubjectsOfEveryType() map[string]any {
	return map[string]any{
		"a number":       float64(5),
		"a boolean":      true,
		"an array":       []any{"openid"},
		"an object":      map[string]any{},
		"an empty array": []any{},
		"a string":       "openid profile",
	}
}

func applyScopePolicy(t *testing.T, subject any, present bool, operators string) (any, bool, error) {
	t.Helper()
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"scope":`+operators+`}}`), &policy); err != nil {
		t.Fatalf("the policy fixture did not parse: %v", err)
	}
	metadata := OpenIDRelyingPartyMetadata{"redirect_uris": []any{"https://leaf.example.com/cb"}}
	if present {
		metadata["scope"] = subject
	}
	result, err := ApplyPolicy(EntityStatement{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &metadata}}, policy)
	if err != nil {
		return nil, false, err
	}
	scope, ok := (*result.Metadata.OpenIDRelyingPartyMetadata)["scope"]
	return scope, ok, nil
}

func TestApplyPolicy_AValueOverAnyScopeIsAssignedAsAString(t *testing.T) {
	policies := map[string]string{
		"a string value":           `{"value":"openid email"}`,
		"an array value":           `{"value":["openid","email"]}`,
		"a value then essential":   `{"value":"openid email","essential":true}`,
		"a value then default":     `{"value":"openid email","default":"profile"}`,
		"a value then superset_of": `{"value":"openid email","superset_of":["openid"]}`,
		"a value then subset_of":   `{"value":"openid email profile","subset_of":["openid","email"]}`,
	}
	for subjectName, subject := range scopeSubjectsOfEveryType() {
		for policyName, operators := range policies {
			t.Run(fmt.Sprintf("%s over %s", policyName, subjectName), func(t *testing.T) {
				scope, ok, err := applyScopePolicy(t, subject, true, operators)
				if err != nil {
					t.Fatalf("[6.1.3.1.1] expected the value to be assigned, got %v", err)
				}
				if !ok || scope != "openid email" {
					t.Fatalf("[6.1.3.1.1, 6.1.3.1.8] expected the scope to be assigned the value as the string \"openid email\", got %#v", scope)
				}
				metadata := map[string]any{"scope": scope}
				if err := VerifyScopeClaim(metadata); err != nil {
					t.Errorf("[6.1.3.1.8] expected the assigned scope to pass the checks of the entity type, got %v", err)
				}
			})
		}
	}
}

func TestApplyPolicy_AValueThenAddOverAnyScopeIsAString(t *testing.T) {
	for subjectName, subject := range scopeSubjectsOfEveryType() {
		t.Run(subjectName, func(t *testing.T) {
			scope, _, err := applyScopePolicy(t, subject, true, `{"value":"openid email","add":["profile"]}`)
			if err != nil {
				t.Fatalf("[6.1.3.1.3] expected add to extend the assigned value, got %v", err)
			}
			if scope != "openid email profile" {
				t.Fatalf("[6.1.3.1.3, 6.1.3.1.8] expected \"openid email profile\", got %#v", scope)
			}
		})
	}
}

func TestApplyPolicy_AValuePointerOverANonStringScopeIsAssignedAsAString(t *testing.T) {
	value, err := NewValue("openid email")
	if err != nil {
		t.Fatalf("the value operator did not build: %v", err)
	}
	policy := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
		"scope": {Metadata: []MetadataPolicyOperator{value}},
	}}
	metadata := OpenIDRelyingPartyMetadata{"scope": float64(5)}

	result, err := ApplyPolicy(EntityStatement{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &metadata}}, policy)

	if err != nil {
		t.Fatalf("[6.1.3.1.1] expected the value to be assigned, got %v", err)
	}
	if got := (*result.Metadata.OpenIDRelyingPartyMetadata)["scope"]; got != "openid email" {
		t.Fatalf("[6.1.3.1.1, 6.1.3.1.8] expected \"openid email\", got %#v", got)
	}
}

func TestApplyPolicy_ANonStringValueOverAnyScopeIsAssignedAsItIs(t *testing.T) {
	values := map[string]any{
		"a number":                       float64(5),
		"a boolean":                      true,
		"an object":                      map[string]any{"a": float64(1)},
		"an array holding a non-string":  []any{"openid", float64(5)},
		"an array holding only a number": []any{float64(5)},
	}
	for subjectName, subject := range scopeSubjectsOfEveryType() {
		for valueName, value := range values {
			t.Run(fmt.Sprintf("%s over %s", valueName, subjectName), func(t *testing.T) {
				operand, err := json.Marshal(value)
				if err != nil {
					t.Fatalf("the operand fixture did not encode: %v", err)
				}
				scope, _, err := applyScopePolicy(t, subject, true, `{"value":`+string(operand)+`}`)
				if err != nil {
					t.Fatalf("[6.1.3.1.1] expected the value to be assigned, got %v", err)
				}
				if !reflect.DeepEqual(scope, value) {
					t.Fatalf("[6.1.3.1.1] expected the scope to be assigned %#v, got %#v", value, scope)
				}
				if err := VerifyScopeClaim(map[string]any{"scope": scope}); err == nil {
					t.Errorf("[6.1.3.1.8] expected the checks of the entity type to refuse a scope that is not a string")
				}
			})
		}
	}
}

func TestApplyPolicy_AnOperatorThatKeepsANonStringScopeLeavesItsType(t *testing.T) {
	policies := map[string]string{
		"default":   `{"default":"openid email"}`,
		"essential": `{"essential":true}`,
	}
	for subjectName, subject := range scopeSubjectsOfEveryType() {
		if _, isString := subject.(string); isString {
			continue
		}
		for policyName, operators := range policies {
			t.Run(fmt.Sprintf("%s over %s", policyName, subjectName), func(t *testing.T) {
				scope, _, err := applyScopePolicy(t, subject, true, operators)
				if err != nil {
					t.Fatalf("[6.1.3.1.2, 6.1.3.1.7] expected the policy to apply, got %v", err)
				}
				if !reflect.DeepEqual(scope, subject) {
					t.Fatalf("[6.1.3.1.2, 6.1.3.1.7] expected the subject's scope %#v to be kept, got %#v", subject, scope)
				}
			})
		}
	}
}

func TestApplyPolicy_AListOperatorOverAnArrayScopeLeavesAnArray(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		operators string
		expect    any
	}{
		{name: "add", reference: "6.1.3.1.3", operators: `{"add":["email"]}`, expect: []any{"openid", "email"}},
		{name: "subset_of", reference: "6.1.3.1.5", operators: `{"subset_of":["openid","email"]}`, expect: []any{"openid"}},
		{name: "superset_of", reference: "6.1.3.1.6", operators: `{"superset_of":["openid"]}`, expect: []any{"openid"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope, _, err := applyScopePolicy(t, []any{"openid"}, true, tc.operators)
			if err != nil {
				t.Fatalf("[%s] expected the policy to apply, got %v", tc.reference, err)
			}
			if !reflect.DeepEqual(scope, tc.expect) {
				t.Fatalf("[%s] expected %#v, got %#v", tc.reference, tc.expect, scope)
			}
		})
	}
}

func TestApplyPolicy_ADefaultFillingAnAbsentScopeIsAString(t *testing.T) {
	for name, operators := range map[string]string{
		"a string default":         `{"default":"openid email"}`,
		"an array default":         `{"default":["openid","email"]}`,
		"a default then essential": `{"default":["openid","email"],"essential":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			scope, _, err := applyScopePolicy(t, nil, false, operators)
			if err != nil {
				t.Fatalf("[6.1.3.1.2] expected the default to fill the scope, got %v", err)
			}
			if scope != "openid email" {
				t.Fatalf("[6.1.3.1.2, 6.1.3.1.8] expected \"openid email\", got %#v", scope)
			}
		})
	}
}
