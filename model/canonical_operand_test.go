package model

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestOperandSet_DistinguishesValuesThatRenderAlike(t *testing.T) {
	tests := []struct {
		name   string
		a      any
		b      any
		expect bool
	}{
		{
			name: "objects whose key and value boundary differs",
			a:    map[string]any{"a": "b c"},
			b:    map[string]any{"a b": "c"},
		},
		{
			name: "an object member that is a string against the same digits as a number",
			a:    map[string]any{"a": "1"},
			b:    map[string]any{"a": float64(1)},
		},
		{
			name: "nested objects whose inner boundary differs",
			a:    map[string]any{"a": map[string]any{"b": "c d"}},
			b:    map[string]any{"a": map[string]any{"b c": "d"}},
		},
		{
			name:   "the same object with its keys written in a different order",
			a:      map[string]any{"a": 1, "b": 2},
			b:      map[string]any{"b": 2, "a": 1},
			expect: true,
		},
		{
			name:   "the same nested object",
			a:      map[string]any{"a": map[string]any{"c": 3, "b": 2}},
			b:      map[string]any{"a": map[string]any{"b": 2, "c": 3}},
			expect: true,
		},
		{
			name: "a string against the digits it contains",
			a:    "1",
			b:    float64(1),
		},
		{
			name: "an array against an object",
			a:    []any{"a"},
			b:    map[string]any{"0": "a"},
		},
		{
			name:   "identical arrays",
			a:      []any{"a", "b"},
			b:      []any{"a", "b"},
			expect: true,
		},
		{
			name: "arrays differing only in order",
			a:    []any{"a", "b"},
			b:    []any{"b", "a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsOperand([]any{tc.a}, tc.b); got != tc.expect {
				t.Errorf("expected membership %v, got %v", tc.expect, got)
			}
			if got := containsOperand([]any{tc.b}, tc.a); got != tc.expect {
				t.Errorf("expected membership %v in the other direction, got %v", tc.expect, got)
			}
		})
	}
}

func TestOperandSet_FallsBackForValuesWithNoCanonicalForm(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		expect bool
	}{
		{name: "a channel matches itself by deep equality", value: make(chan int), expect: true},
		{name: "a function has no canonical form", value: func() {}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := canonicalOperandKey(tc.value); ok {
				t.Fatal("expected this value to have no canonical form")
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a value with no canonical form panicked: %v", r)
				}
			}()
			if got := containsOperand([]any{tc.value}, tc.value); got != tc.expect {
				t.Errorf("expected membership %v, got %v", tc.expect, got)
			}
		})
	}

	t.Run("a NaN has no canonical form and is not equal to itself", func(t *testing.T) {
		if _, ok := canonicalOperandKey(math.NaN()); ok {
			t.Fatal("expected NaN to have no canonical form")
		}
		if containsOperand([]any{math.NaN()}, math.NaN()) {
			t.Error("expected NaN not to be equal to NaN, matching Go and IEEE 754")
		}
	})
}

func TestDeduplicateSlice_KeepsValuesThatRenderAlike(t *testing.T) {
	tests := []struct {
		name   string
		input  []any
		expect int
	}{
		{
			name:   "objects whose key and value boundary differs",
			input:  []any{map[string]any{"a": "b c"}, map[string]any{"a b": "c"}},
			expect: 2,
		},
		{
			name:   "a string member against the same digits as a number",
			input:  []any{map[string]any{"a": "1"}, map[string]any{"a": float64(1)}},
			expect: 2,
		},
		{
			name:   "genuinely identical objects collapse",
			input:  []any{map[string]any{"a": "b"}, map[string]any{"a": "b"}},
			expect: 1,
		},
		{
			name:   "the same object with keys in a different order collapses",
			input:  []any{map[string]any{"a": 1, "b": 2}, map[string]any{"b": 2, "a": 1}},
			expect: 1,
		},
		{
			name:   "identical strings collapse",
			input:  []any{"a", "a", "b"},
			expect: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DeduplicateSlice(tc.input)
			if len(got) != tc.expect {
				raw, _ := json.Marshal(got)
				t.Errorf("expected %d values, got %d: %s", tc.expect, len(got), raw)
			}
		})
	}
}

func TestOperators_RetainDistinctObjectOperands(t *testing.T) {
	operators := []string{"value", "add", "one_of", "subset_of", "superset_of", "default"}

	for _, operator := range operators {
		t.Run(operator, func(t *testing.T) {
			raw := `{"` + operator + `":[{"a":"b c"},{"a b":"c"}]}`
			var parsed PolicyOperators
			if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
				t.Fatalf("the fixture did not parse: %v", err)
			}
			if len(parsed.Metadata) != 1 {
				t.Fatalf("expected one operator, got %d", len(parsed.Metadata))
			}

			value, ok := parsed.Metadata[0].OperatorValue().([]any)
			if !ok {
				t.Fatalf("expected an array operand, got %T", parsed.Metadata[0].OperatorValue())
			}
			if len(value) != 2 {
				out, _ := json.Marshal(value)
				t.Fatalf("[6.1.3.1] expected both distinct objects to be retained, got %s", out)
			}
		})
	}
}

func TestMergePolicyOperators_SupersetOfKeepsBothRequirements(t *testing.T) {
	var anchor, intermediate PolicyOperators
	if err := json.Unmarshal([]byte(`{"superset_of":[{"a b":"c"}]}`), &anchor); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"superset_of":[{"a":"b c"}]}`), &intermediate); err != nil {
		t.Fatal(err)
	}

	merged, err := MergePolicyOperators("claims", anchor, intermediate)
	if err != nil {
		t.Fatalf("expected the two requirements to merge, got %v", err)
	}
	value, ok := merged[0].OperatorValue().([]any)
	if !ok {
		t.Fatalf("expected an array operand, got %T", merged[0].OperatorValue())
	}
	if len(value) != 2 {
		out, _ := json.Marshal(value)
		t.Fatalf("a subordinate must not be able to replace a superior's required object, got %s", out)
	}

	keys := make([]string, 0, 2)
	for _, v := range value {
		key, _ := canonicalOperandKey(v)
		keys = append(keys, key)
	}
	joined := strings.Join(keys, " ")
	for _, want := range []string{`{"a b":"c"}`, `{"a":"b c"}`} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected the merged requirement to retain %s, got %s", want, joined)
		}
	}
}

func TestOneOfResolve_UsesCanonicalOperandEquality(t *testing.T) {
	tests := []struct {
		name     string
		operands []any
		metadata any
		resolves bool
	}{
		{
			name:     "an object operand that matches the metadata value",
			operands: []any{map[string]any{"a": "b"}},
			metadata: map[string]any{"a": "b"},
			resolves: true,
		},
		{
			name:     "an object operand whose keys are written in a different order",
			operands: []any{map[string]any{"a": 1, "b": 2}},
			metadata: map[string]any{"b": 2, "a": 1},
			resolves: true,
		},
		{
			name:     "an object operand carrying the same JSON under a different Go type",
			operands: []any{map[string]string{"a": "b"}},
			metadata: map[string]any{"a": "b"},
			resolves: true,
		},
		{
			name:     "a number operand carrying the same JSON under a different Go type",
			operands: []any{1},
			metadata: float64(1),
			resolves: true,
		},
		{
			name:     "an object operand that renders like the metadata value but differs",
			operands: []any{map[string]any{"a": "1"}},
			metadata: map[string]any{"a": float64(1)},
		},
		{
			name:     "an object operand whose member boundary differs",
			operands: []any{map[string]any{"a": "b c"}},
			metadata: map[string]any{"a b": "c"},
		},
		{
			name:     "a string operand against the digits it contains",
			operands: []any{"1"},
			metadata: float64(1),
		},
		{
			name:     "a scalar operand present in the list",
			operands: []any{"a", "b"},
			metadata: "b",
			resolves: true,
		},
		{
			name:     "a scalar operand absent from the list",
			operands: []any{"a", "b"},
			metadata: "c",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewOneOf(test.operands)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}

			resolved, err := operator.Resolve(test.metadata)
			if test.resolves {
				if err != nil {
					t.Fatalf("expected the metadata value to resolve, got error: %v", err)
				}
				if !reflect.DeepEqual(resolved, test.metadata) {
					t.Errorf("expected the metadata value %v to be returned, got %v", test.metadata, resolved)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected the metadata value %v to be rejected, got %v", test.metadata, resolved)
			}
		})
	}
}
