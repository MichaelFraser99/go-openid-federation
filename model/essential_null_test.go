package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyOperators_EssentialTakesABooleanOnly(t *testing.T) {
	tests := map[string]struct {
		operand  string
		accepted bool
	}{
		"true":              {operand: `true`, accepted: true},
		"false":             {operand: `false`, accepted: true},
		"null":              {operand: `null`},
		"a string":          {operand: `"true"`},
		"a number":          {operand: `1`},
		"an array":          {operand: `[true]`},
		"an object":         {operand: `{}`},
		"an empty array":    {operand: `[]`},
		"the number zero":   {operand: `0`},
		"the empty string":  {operand: `""`},
		"an array of nulls": {operand: `[null]`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy MetadataPolicy
			err := json.Unmarshal([]byte(`{"openid_relying_party":{"x":{"essential":`+tc.operand+`}}}`), &policy)
			if tc.accepted {
				if err != nil {
					t.Fatalf("[6.1.3.1.7] expected a boolean operand to parse, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[6.1.3] essential with %s must produce a policy error", tc.operand)
			}
			if !strings.Contains(err.Error(), "essential") {
				t.Errorf("expected the error to name the operator, got %v", err)
			}
		})
	}
}

func TestPolicyOperators_AnOmittedEssentialIsStillFalse(t *testing.T) {
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"x":{"default":"a"}}}`), &policy); err != nil {
		t.Fatalf("[6.1.3.1.7] omitting essential must still parse, got %v", err)
	}
}
