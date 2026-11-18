package model

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestApplyPolicyToMetadata_KeepsTheArraysTheClausesDoNotRewrite(t *testing.T) {
	tests := map[string]struct {
		policy   string
		metadata map[string]any
		want     any
	}{
		"add keeps a value the subject published twice": {
			policy:   `{"add":["y"]}`,
			metadata: map[string]any{"x": []any{"a", "a"}},
			want:     []any{"a", "a", "y"},
		},
		"add does not add a value already present": {
			policy:   `{"add":["a"]}`,
			metadata: map[string]any{"x": []any{"a", "a"}},
			want:     []any{"a", "a"},
		},
		"add does not add its own repeated value a second time": {
			policy:   `{"add":["y","y"]}`,
			metadata: map[string]any{"x": []any{"a"}},
			want:     []any{"a", "y"},
		},
		"add initialises an absent parameter with its operand as written": {
			policy:   `{"add":["y","y"]}`,
			metadata: map[string]any{},
			want:     []any{"y", "y"},
		},
		"add on an empty parameter does not add its own repeat a second time": {
			policy:   `{"add":["y","y"]}`,
			metadata: map[string]any{"x": []any{}},
			want:     []any{"y"},
		},
		"value assigns its operand as written": {
			policy:   `{"value":["a","a","b"]}`,
			metadata: map[string]any{"x": []any{"c"}},
			want:     []any{"a", "a", "b"},
		},
		"default sets its operand as written": {
			policy:   `{"default":["a","a"]}`,
			metadata: map[string]any{},
			want:     []any{"a", "a"},
		},
		"value and add together keep the value as written": {
			policy:   `{"value":["a","a"],"add":["a"]}`,
			metadata: map[string]any{"x": []any{"c"}},
			want:     []any{"a", "a"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(`{"openid_relying_party":{"x":`+tc.policy+`}}`), &policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
			if err := applyPolicyToMetadata(tc.metadata, policy.OpenIDRelyingPartyMetadata); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(tc.metadata["x"], tc.want) {
				t.Errorf("[6.1.3.1] expected %#v, got %#v", tc.want, tc.metadata["x"])
			}
		})
	}
}

func TestMergePolicyOperators_ComparesValueAndDefaultOperandsAsWritten(t *testing.T) {
	tests := map[string]struct {
		upper, lower string
		merges       bool
		asSet        bool
		want         any
	}{
		"value with a repeat against value without":      {upper: `{"value":["a","a"]}`, lower: `{"value":["a"]}`},
		"value with a repeat against the same value":     {upper: `{"value":["a","a"]}`, lower: `{"value":["a","a"]}`, merges: true, want: []any{"a", "a"}},
		"default with a repeat against default without":  {upper: `{"default":["a","a"]}`, lower: `{"default":["a"]}`},
		"default with a repeat against the same default": {upper: `{"default":["a","a"]}`, lower: `{"default":["a","a"]}`, merges: true, want: []any{"a", "a"}},
		"add with a repeat is merged as a union":         {upper: `{"add":["a","a"]}`, lower: `{"add":["b"]}`, merges: true, asSet: true, want: []any{"a", "b"}},
		"add is merged as a union":                       {upper: `{"add":["a","b"]}`, lower: `{"add":["b","c"]}`, merges: true, asSet: true, want: []any{"a", "b", "c"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var upper, lower PolicyOperators
			if err := json.Unmarshal([]byte(tc.upper), &upper); err != nil {
				t.Fatalf("failed to parse the upper policy: %v", err)
			}
			if err := json.Unmarshal([]byte(tc.lower), &lower); err != nil {
				t.Fatalf("failed to parse the lower policy: %v", err)
			}
			merged, err := MergePolicyOperators("x", upper, lower)
			if !tc.merges {
				if err == nil {
					t.Fatalf("[6.1.3.1] expected operands that are not equal as written to be a policy error, got %v", merged)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the operators to merge, got %v", err)
			}
			if len(merged) != 1 {
				t.Fatalf("expected one merged operator, got %#v", merged)
			}
			got := merged[0].OperatorValue()
			if tc.asSet {
				values, _ := got.([]any)
				got = slices.SortedFunc(slices.Values(slices.Clone(values)), func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("[6.1.3.1] expected one operator holding %#v, got %#v", tc.want, merged)
			}
		})
	}
}

func TestAdd_MergeIsAUnionWhateverTheArgumentRepeats(t *testing.T) {
	operator, err := NewAdd([]any{"b"})
	if err != nil {
		t.Fatalf("failed to build the operator: %v", err)
	}
	merged, err := operator.Merge([]any{"a", "a"})
	if err != nil {
		t.Fatalf("expected the operators to merge, got %v", err)
	}
	values, _ := merged.OperatorValue().([]any)
	if len(values) != 2 || !slices.Contains(values, "a") || !slices.Contains(values, "b") {
		t.Errorf("[6.1.3.1.2] expected the union of the values to be a and b once each, got %#v", values)
	}
}
