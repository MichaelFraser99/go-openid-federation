package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestApplyPolicyToMetadata_ValueReplacesAParameterOfAnotherType(t *testing.T) {
	values := map[string]any{
		"string":  "a",
		"number":  float64(1),
		"boolean": true,
		"array":   []any{"a"},
		"object":  map[string]any{"keys": []any{}},
	}

	for existingType, existing := range values {
		for operandType, operand := range values {
			t.Run(existingType+" replaced by "+operandType, func(t *testing.T) {
				raw, err := json.Marshal(map[string]any{"openid_relying_party": map[string]any{"x": map[string]any{"value": operand}}})
				if err != nil {
					t.Fatalf("failed to build the policy: %v", err)
				}
				var policy MetadataPolicy
				if err := json.Unmarshal(raw, &policy); err != nil {
					t.Fatalf("failed to parse the policy: %v", err)
				}
				metadata := map[string]any{"x": existing}
				if err := applyPolicyToMetadata(metadata, policy.OpenIDRelyingPartyMetadata); err != nil {
					t.Fatalf("[6.1.3.1.1] expected the operator value to be assigned, got %v", err)
				}
				if !reflect.DeepEqual(metadata["x"], operand) {
					t.Errorf("[6.1.3.1.1] expected %#v, got %#v", operand, metadata["x"])
				}
			})
		}
	}

	t.Run("null removes a parameter of any type", func(t *testing.T) {
		var policy MetadataPolicy
		if err := json.Unmarshal([]byte(`{"openid_relying_party":{"x":{"value":null}}}`), &policy); err != nil {
			t.Fatalf("failed to parse the policy: %v", err)
		}
		for existingType, existing := range values {
			metadata := map[string]any{"x": existing}
			if err := applyPolicyToMetadata(metadata, policy.OpenIDRelyingPartyMetadata); err != nil {
				t.Fatalf("expected null to remove a %s, got %v", existingType, err)
			}
			if _, present := metadata["x"]; present {
				t.Errorf("[6.1.3.1.1] expected null to remove a %s, got %#v", existingType, metadata["x"])
			}
		}
	})
}
