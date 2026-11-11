package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyOperators_AParameterPolicyThatIsNotAnObjectIsDescribedByKind(t *testing.T) {
	const marker = "jpsQnnGQmL-YBIffH1136cLvhgLlb8TXx0cfw3xQk9Q"

	tests := map[string]struct {
		policy string
		kind   string
	}{
		"an array":  {policy: `[{"kty":"EC","d":"` + marker + `"}]`, kind: "an array"},
		"a string":  {policy: `"` + marker + `"`, kind: "a string"},
		"a number":  {policy: `4242`, kind: "a number"},
		"a boolean": {policy: `true`, kind: "a boolean"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy MetadataPolicy
			err := json.Unmarshal([]byte(`{"federation_entity":{"contacts":`+tc.policy+`}}`), &policy)
			if err == nil {
				t.Fatalf("[6.1] expected a parameter policy that is not a JSON object to be refused")
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "4242") {
				t.Errorf("expected the policy described by its kind, but the error echoes its value: %v", err)
			}
			if !strings.Contains(err.Error(), "must be a JSON object, not "+tc.kind) {
				t.Errorf("expected the error to name %s, got %v", tc.kind, err)
			}
		})
	}
}

func TestPolicyOperators_UnmarshalJSONCalledDirectlyNamesTheKindItWasGiven(t *testing.T) {
	tests := map[string]struct {
		input string
		kind  string
	}{
		"an array after whitespace": {input: "  [1]", kind: "an array"},
		"a negative number":         {input: "-1", kind: "a number"},
		"text that is not JSON":     {input: "xyz", kind: "a value that is not valid JSON"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var operators PolicyOperators
			err := operators.UnmarshalJSON([]byte(tc.input))
			if err == nil || !strings.Contains(err.Error(), "must be a JSON object, not "+tc.kind) {
				t.Errorf("expected the error to name %s, got %v", tc.kind, err)
			}
		})
	}

	for name, input := range map[string]string{
		"an object after whitespace": "  {}",
		"null after whitespace":      " null ",
		"only whitespace":            "   ",
	} {
		t.Run(name, func(t *testing.T) {
			var operators PolicyOperators
			if err := operators.UnmarshalJSON([]byte(input)); err != nil {
				t.Errorf("expected %q to be read as it is when it arrives through encoding/json, got %v", input, err)
			}
		})
	}
}
