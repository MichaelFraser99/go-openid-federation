package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyOperators_AListOperatorTakesAnArrayOfStringsNumbersOrObjects(t *testing.T) {
	operators := []string{"add", "one_of", "subset_of", "superset_of"}
	tests := map[string]struct {
		operand   string
		expectErr string
	}{
		"an empty array":                     {operand: `[]`},
		"an array of strings":                {operand: `["a","b"]`},
		"an array of numbers":                {operand: `[1,2.5,-0]`},
		"an array of objects":                {operand: `[{"a":1},{"b":[true]}]`},
		"an array of booleans":               {operand: `[true,false]`, expectErr: "holds a boolean"},
		"an array of arrays":                 {operand: `[["a"]]`, expectErr: "holds an array"},
		"an array holding null":              {operand: `[null]`, expectErr: "holds null"},
		"strings then a number":              {operand: `["a",1]`, expectErr: "mixes strings and numbers"},
		"a number then a string":             {operand: `[1,"a"]`, expectErr: "mixes numbers and strings"},
		"an object then a string":            {operand: `[{"a":1},"b"]`, expectErr: "mixes objects and strings"},
		"strings with a boolean at the end":  {operand: `["a","b",true]`, expectErr: "holds a boolean"},
		"a string that looks like a boolean": {operand: `["true"]`},
	}

	for _, operator := range operators {
		for name, tc := range tests {
			t.Run(operator+", "+name, func(t *testing.T) {
				var policy MetadataPolicy
				err := json.Unmarshal([]byte(`{"openid_relying_party":{"x":{"`+operator+`":`+tc.operand+`}}}`), &policy)
				if tc.expectErr == "" {
					if err != nil {
						t.Fatalf("[6.1.3.1] expected %s to accept %s, got %v", operator, tc.operand, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("[6.1.3] %s with %s must produce a policy error", operator, tc.operand)
				}
				if !strings.Contains(err.Error(), tc.expectErr) || !strings.Contains(err.Error(), operator) {
					t.Errorf("expected an error naming %q and the operator, got %v", tc.expectErr, err)
				}
			})
		}
	}
}

func TestPolicyOperators_AListOperatorBuiltFromGoTypesIsJudgedTheSameWay(t *testing.T) {
	constructors := map[string]func(any) error{
		"add":         func(v any) error { _, err := NewAdd(v); return err },
		"one_of":      func(v any) error { _, err := NewOneOf(v); return err },
		"subset_of":   func(v any) error { _, err := NewSubsetOf(v); return err },
		"superset_of": func(v any) error { _, err := NewSupersetOf(v); return err },
	}
	tests := map[string]struct {
		operand  any
		accepted bool
	}{
		"a []string":                            {operand: []string{"a"}, accepted: true},
		"a []int":                               {operand: []int{1, 2}, accepted: true},
		"a []uint8":                             {operand: []uint8{1}, accepted: true},
		"a []float32":                           {operand: []float32{1.5}, accepted: true},
		"a []map[string]any":                    {operand: []map[string]any{{"a": 1}}, accepted: true},
		"a []bool":                              {operand: []bool{true}},
		"a []any mixing int and string":         {operand: []any{1, "a"}},
		"a map keyed by something not a string": {operand: []any{map[int]any{1: "a"}}},
	}

	for operator, construct := range constructors {
		for name, tc := range tests {
			t.Run(operator+", "+name, func(t *testing.T) {
				err := construct(tc.operand)
				if tc.accepted && err != nil {
					t.Fatalf("expected %s to accept %#v, got %v", operator, tc.operand, err)
				}
				if !tc.accepted && err == nil {
					t.Fatalf("[6.1.3] expected %s to refuse %#v", operator, tc.operand)
				}
			})
		}
	}
}

func TestProcessAndExtractPolicy_MergingOperandsOfDifferentTypesIsAPolicyError(t *testing.T) {
	const (
		leaf         = EntityIdentifier("https://leaf.example.com")
		intermediate = EntityIdentifier("https://int.example.com")
		anchor       = EntityIdentifier("https://ta.example.com")
	)

	for _, operator := range []string{"add", "superset_of"} {
		t.Run(operator, func(t *testing.T) {
			chain := []EntityStatement{
				{Iss: leaf, Sub: leaf},
				{Iss: intermediate, Sub: leaf, MetadataPolicy: chainPolicy(t, `{"openid_relying_party":{"x":{"`+operator+`":["a"]}}}`)},
				{Iss: anchor, Sub: intermediate, MetadataPolicy: chainPolicy(t, `{"openid_relying_party":{"x":{"`+operator+`":[1]}}}`)},
				{Iss: anchor, Sub: anchor},
			}
			if _, err := ProcessAndExtractPolicy(chain); err == nil {
				t.Fatalf("[6.1.3] two levels whose operands combine into a mixed array must produce a policy error, got %v", err)
			}
		})
	}
}
