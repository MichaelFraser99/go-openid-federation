package model

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOperands_NegativeZeroIsZero(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		metadata string
		resolved string
	}{
		{
			name:     "superset_of requiring zero against metadata carrying negative zero",
			policy:   `{"superset_of":[0]}`,
			metadata: `[-0]`,
			resolved: `[-0]`,
		},
		{
			name:     "superset_of requiring negative zero against metadata carrying zero",
			policy:   `{"superset_of":[-0]}`,
			metadata: `[0]`,
			resolved: `[0]`,
		},
		{
			name:     "subset_of allowing zero against metadata carrying negative zero",
			policy:   `{"subset_of":[0]}`,
			metadata: `[-0]`,
			resolved: `[-0]`,
		},
		{
			name:     "an object member holding negative zero against the same member holding zero",
			policy:   `{"superset_of":[{"a":-0}]}`,
			metadata: `[{"a":0}]`,
			resolved: `[{"a":0}]`,
		},
		{
			name:     "a nested object member holding negative zero",
			policy:   `{"superset_of":[{"a":{"b":-0}}]}`,
			metadata: `[{"a":{"b":0}}]`,
			resolved: `[{"a":{"b":0}}]`,
		},
		{
			name:     "an array member holding negative zero",
			policy:   `{"superset_of":[[-0]]}`,
			metadata: `[[0]]`,
			resolved: `[[0]]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var operators PolicyOperators
			if err := json.Unmarshal([]byte(test.policy), &operators); err != nil {
				t.Fatalf("no error expected decoding the policy, got: %v", err)
			}
			var metadata []any
			if err := json.Unmarshal([]byte(test.metadata), &metadata); err != nil {
				t.Fatalf("no error expected decoding the metadata, got: %v", err)
			}

			resolved, err := operators.Metadata[0].Resolve(metadata)
			if err != nil {
				t.Fatalf("zero and negative zero are the same JSON number, got error: %v", err)
			}
			out, err := json.Marshal(resolved)
			if err != nil {
				t.Fatalf("no error expected encoding the resolved value, got: %v", err)
			}
			if string(out) != test.resolved {
				t.Errorf("expected %s, got %s", test.resolved, out)
			}
		})
	}
}

func TestOperands_OneOfAcceptsNegativeZero(t *testing.T) {
	var operators PolicyOperators
	if err := json.Unmarshal([]byte(`{"one_of":[0,1]}`), &operators); err != nil {
		t.Fatal(err)
	}
	var metadata any
	if err := json.Unmarshal([]byte(`-0`), &metadata); err != nil {
		t.Fatal(err)
	}
	if !math.Signbit(metadata.(float64)) {
		t.Fatal("the decoded metadata value must carry the sign bit for this test to mean anything")
	}

	if _, err := operators.Metadata[0].Resolve(metadata); err != nil {
		t.Errorf("zero and negative zero are the same JSON number, got error: %v", err)
	}
}

func TestOperands_StringsWithNoJSONEncodingStayDistinct(t *testing.T) {
	first := string([]byte{0xff})
	second := string([]byte{0xfe})
	third := string([]byte{0xff, 'A'})

	deduplicated := DeduplicateSlice([]any{first, second, third, first})
	if len(deduplicated) != 3 {
		t.Errorf("expected three distinct byte sequences to survive, got %d", len(deduplicated))
	}

	operator, err := NewOneOf([]any{first})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Resolve("�"); err == nil {
		t.Error("the replacement character must not satisfy an operand holding a raw invalid byte")
	}
	if _, err := operator.Resolve(first); err != nil {
		t.Errorf("an operand must satisfy itself, got error: %v", err)
	}

	containers := []struct {
		name  string
		first any
		other any
	}{
		{
			name:  "an object member name",
			first: map[string]any{string([]byte{0xff}): "a"},
			other: map[string]any{string([]byte{0xfe}): "a"},
		},
		{
			name:  "an object member value",
			first: map[string]any{"a": string([]byte{0xff})},
			other: map[string]any{"a": string([]byte{0xfe})},
		},
		{
			name:  "an array member",
			first: []any{string([]byte{0xff})},
			other: []any{string([]byte{0xfe})},
		},
		{
			name:  "a Go string slice",
			first: []string{string([]byte{0xff})},
			other: []string{string([]byte{0xfe})},
		},
		{
			name:  "a Go string map value",
			first: map[string]string{"a": string([]byte{0xff})},
			other: map[string]string{"a": string([]byte{0xfe})},
		},
		{
			name:  "a Go string map member name",
			first: map[string]string{string([]byte{0xff}): "a"},
			other: map[string]string{string([]byte{0xfe}): "a"},
		},
		{
			name:  "a nested object member value",
			first: map[string]any{"a": map[string]any{"b": string([]byte{0xff})}},
			other: map[string]any{"a": map[string]any{"b": string([]byte{0xfe})}},
		},
	}

	for _, container := range containers {
		t.Run(container.name, func(t *testing.T) {
			if got := DeduplicateSlice([]any{container.first, container.other}); len(got) != 2 {
				t.Errorf("expected two distinct values to survive deduplication, got %d", len(got))
			}
		})
	}
}

func TestOperands_ValuesThatCannotMatchDoNotAccumulate(t *testing.T) {
	const count = 8000
	const budget = 250 * time.Millisecond

	input := make([]any, count)
	for i := range input {
		input[i] = math.NaN()
	}

	start := time.Now()
	deduplicated := DeduplicateSlice(input)
	elapsed := time.Since(start)

	if len(deduplicated) != count {
		t.Errorf("a NaN is not equal to itself, so every one must survive, got %d of %d", len(deduplicated), count)
	}
	if elapsed > budget {
		t.Errorf("deduplicating %d values that cannot match took %v, which is the quadratic scan", count, elapsed)
	}

	if isSubsetOfOperands([]any{math.NaN()}, input) {
		t.Error("a NaN is not equal to itself, so it is a member of no operand set")
	}

	set := newOperandSet([]any{math.NaN(), math.NaN(), "a", string([]byte{0xff})})
	if set.fallbackCount() != 1 {
		t.Errorf("only the value that can match itself belongs in the fallback bucket, got %d entries", set.fallbackCount())
	}
}

func TestOperands_AddDeduplicatesValuesWithNoJSONEncoding(t *testing.T) {
	tests := []struct {
		name     string
		metadata []any
		operand  []any
		expect   int
	}{
		{
			name:     "an infinity already present in the metadata",
			metadata: []any{"x", math.Inf(1)},
			operand:  []any{math.Inf(1)},
			expect:   2,
		},
		{
			name:     "an invalid byte sequence already present in the metadata",
			metadata: []any{string([]byte{0xff})},
			operand:  []any{string([]byte{0xff})},
			expect:   1,
		},
		{
			name:     "an object whose member names differ only in an invalid byte",
			metadata: []any{map[string]any{string([]byte{0xff}): "a"}},
			operand:  []any{map[string]any{string([]byte{0xfe}): "a"}},
			expect:   2,
		},
		{
			name:     "an operand the metadata does not hold",
			metadata: []any{"x"},
			operand:  []any{math.Inf(1)},
			expect:   2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewAdd(test.operand)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}
			resolved, err := operator.Resolve(test.metadata)
			if err != nil {
				t.Fatalf("no error expected resolving, got: %v", err)
			}
			got, ok := resolved.([]any)
			if !ok {
				t.Fatalf("expected an array, got %T", resolved)
			}
			if len(got) != test.expect {
				t.Errorf("expected %d values, got %d: %v", test.expect, len(got), got)
			}
		})
	}
}

func TestOperands_ConflictChecksShareTheEqualityRule(t *testing.T) {
	tests := []struct {
		name      string
		operators func(*testing.T) []MetadataPolicyOperator
		conflict  bool
	}{
		{
			name: "add against value holding the same number as a different Go type",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustValue(t, []any{float64(1)}), mustAdd(t, []any{int(1)})}
			},
		},
		{
			name: "add against value holding a different number",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustValue(t, []any{float64(2)}), mustAdd(t, []any{int(1)})}
			},
			conflict: true,
		},
		{
			name: "add against subset_of holding the same number as a different Go type",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSubsetOf(t, []any{float64(1)}), mustAdd(t, []any{int(1)})}
			},
		},
		{
			name: "add against subset_of holding a different number",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSubsetOf(t, []any{float64(2)}), mustAdd(t, []any{int(1)})}
			},
			conflict: true,
		},
		{
			name: "value against one_of holding the same number as a different Go type",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustOneOf(t, []any{float64(1)}), mustValue(t, int(1))}
			},
		},
		{
			name: "value against one_of holding a different number",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustOneOf(t, []any{float64(2)}), mustValue(t, int(1))}
			},
			conflict: true,
		},
		{
			name: "value against subset_of holding the same number as a different Go type",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSubsetOf(t, []any{float64(1)}), mustValue(t, []any{int(1)})}
			},
		},
		{
			name: "value against subset_of holding a different number",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSubsetOf(t, []any{float64(2)}), mustValue(t, []any{int(1)})}
			},
			conflict: true,
		},
		{
			name: "value against superset_of holding the same number as a different Go type",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSupersetOf(t, []any{int(1)}), mustValue(t, []any{float64(1)})}
			},
		},
		{
			name: "value against superset_of holding a different number",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSupersetOf(t, []any{int(2)}), mustValue(t, []any{float64(1)})}
			},
			conflict: true,
		},
		{
			name: "subset_of against superset_of holding the same number as a different Go type",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSubsetOf(t, []any{float64(1)}), mustSupersetOf(t, []any{int(1)})}
			},
		},
		{
			name: "subset_of against superset_of holding a different number",
			operators: func(t *testing.T) []MetadataPolicyOperator {
				return []MetadataPolicyOperator{mustSubsetOf(t, []any{float64(2)}), mustSupersetOf(t, []any{int(1)})}
			},
			conflict: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePoliciesCanCombine(test.operators(t))
			if test.conflict {
				if err == nil {
					t.Error("expected the operators to be reported as conflicting")
				}
				return
			}
			if err != nil {
				t.Errorf("the two operands are the same JSON number, got conflict: %v", err)
			}
		})
	}
}

func TestOperands_MergeSharesTheEqualityRule(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T) (MetadataPolicyOperator, any)
		merge bool
	}{
		{
			name: "value merged with the same number as a different Go type",
			build: func(t *testing.T) (MetadataPolicyOperator, any) {
				return mustValue(t, []any{int(1)}), []any{float64(1)}
			},
			merge: true,
		},
		{
			name: "value merged with a different number",
			build: func(t *testing.T) (MetadataPolicyOperator, any) {
				return mustValue(t, []any{int(1)}), []any{float64(2)}
			},
		},
		{
			name: "default merged with the same number as a different Go type",
			build: func(t *testing.T) (MetadataPolicyOperator, any) {
				return mustDefault(t, []any{int(1)}), []any{float64(1)}
			},
			merge: true,
		},
		{
			name: "default merged with a different number",
			build: func(t *testing.T) (MetadataPolicyOperator, any) {
				return mustDefault(t, []any{int(1)}), []any{float64(2)}
			},
		},
		{
			name: "value merged with an object whose members are written in a different order",
			build: func(t *testing.T) (MetadataPolicyOperator, any) {
				return mustValue(t, map[string]any{"a": 1, "b": 2}), map[string]any{"b": 2, "a": 1}
			},
			merge: true,
		},
		{
			name: "value merged with an object that renders alike but differs",
			build: func(t *testing.T) (MetadataPolicyOperator, any) {
				return mustValue(t, map[string]any{"a": "b c"}), map[string]any{"a b": "c"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, incoming := test.build(t)
			_, err := operator.Merge(incoming)
			if test.merge {
				if err != nil {
					t.Errorf("the two operands are the same JSON value, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Error("expected the merge to be refused")
			}
		})
	}
}

func mustValue(t *testing.T, operand any) Value {
	t.Helper()
	operator, err := NewValue(operand)
	if err != nil {
		t.Fatalf("no error expected building 'value', got: %v", err)
	}
	return *operator
}

func mustDefault(t *testing.T, operand any) Default {
	t.Helper()
	operator, err := NewDefault(operand)
	if err != nil {
		t.Fatalf("no error expected building 'default', got: %v", err)
	}
	return *operator
}

func mustAdd(t *testing.T, operand []any) Add {
	t.Helper()
	operator, err := NewAdd(operand)
	if err != nil {
		t.Fatalf("no error expected building 'add', got: %v", err)
	}
	return *operator
}

func mustOneOf(t *testing.T, operand []any) OneOf {
	t.Helper()
	operator, err := NewOneOf(operand)
	if err != nil {
		t.Fatalf("no error expected building 'one_of', got: %v", err)
	}
	return *operator
}

func mustSubsetOf(t *testing.T, operand []any) SubsetOf {
	t.Helper()
	operator, err := NewSubsetOf(operand)
	if err != nil {
		t.Fatalf("no error expected building 'subset_of', got: %v", err)
	}
	return *operator
}

func mustSupersetOf(t *testing.T, operand []any) SupersetOf {
	t.Helper()
	operator, err := NewSupersetOf(operand)
	if err != nil {
		t.Fatalf("no error expected building 'superset_of', got: %v", err)
	}
	return *operator
}

func TestOperands_MergePreservesTheCurrentLevelOrder(t *testing.T) {
	const count = 24

	current := make([]any, count)
	incoming := make([]any, 0, count+1)
	for i := range count {
		current[i] = fmt.Sprintf("value-%d", count-1-i)
		incoming = append(incoming, fmt.Sprintf("value-%d", i))
	}
	incoming = append(incoming, "value-extra")

	tests := []struct {
		name  string
		build func(any) (MetadataPolicyOperator, error)
	}{
		{name: "one_of", build: func(v any) (MetadataPolicyOperator, error) { return NewOneOf(v) }},
		{name: "subset_of", build: func(v any) (MetadataPolicyOperator, error) { return NewSubsetOf(v) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := test.build(current)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}
			merged, err := operator.Merge(incoming)
			if err != nil {
				t.Fatalf("no error expected merging, got: %v", err)
			}
			got, ok := merged.OperatorValue().([]any)
			if !ok {
				t.Fatalf("expected an array operand, got %T", merged.OperatorValue())
			}
			if !reflect.DeepEqual(got, current) {
				t.Errorf("expected the current level's order %v, got %v", current, got)
			}
		})
	}
}

func TestOperands_AddUnionIsASet(t *testing.T) {
	tests := []struct {
		name     string
		metadata []any
		operand  []any
		expect   []any
	}{
		{
			name:     "an operand the metadata already holds",
			metadata: []any{"x", "y"},
			operand:  []any{"y"},
			expect:   []any{"x", "y"},
		},
		{
			name:     "an operand listed twice",
			metadata: []any{"x"},
			operand:  []any{"y", "y"},
			expect:   []any{"x", "y"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewAdd(test.operand)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}
			resolved, err := operator.Resolve(test.metadata)
			if err != nil {
				t.Fatalf("no error expected resolving, got: %v", err)
			}
			if !reflect.DeepEqual(resolved, any(test.expect)) {
				t.Errorf("expected %v, got %v", test.expect, resolved)
			}
		})
	}
}

func TestMergePolicyOperators_DoesNotReflectOperandsIntoTheError(t *testing.T) {
	marker := "OPERAND-MARKER-" + strings.Repeat("Z", 32)

	tests := []struct {
		name      string
		reference string
		first     string
		second    string
	}{
		{name: "two levels setting a different value", reference: "8.9", first: `{"value":"` + marker + `-ONE"}`, second: `{"value":"` + marker + `-TWO"}`},
		{name: "two levels setting a different default", reference: "8.9", first: `{"default":"` + marker + `-ONE"}`, second: `{"default":"` + marker + `-TWO"}`},
		{name: "add against an operand that cannot be compared", reference: "8.9", first: `{"add":["` + marker + `-ONE"]}`, second: `{"add":["` + marker + `-TWO"]}`},
		{name: "superset_of against an operand that cannot be compared", reference: "8.9", first: `{"superset_of":["` + marker + `-ONE"]}`, second: `{"superset_of":["` + marker + `-TWO"]}`},
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

			_, err := MergePolicyOperators("client_name", first, second)
			if err == nil {
				return
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("[%s] a superior publishes these operands and the error reaches an unauthenticated caller, so it must not carry them: %v", tc.reference, err)
			}
		})
	}
}

func TestPolicyOperators_CombineErrorsDoNotReflectOperands(t *testing.T) {
	marker := "OPERAND-MARKER-" + strings.Repeat("Q", 32)
	unusable := func() []any { return []any{[]any{marker}} }

	tests := []struct {
		name      string
		reference string
		merge     func() error
	}{
		{
			name:      "add combining an operand it cannot key",
			reference: "8.9",
			merge: func() error {
				_, err := Add{operatorValue: unusable()}.Merge(unusable())
				return err
			},
		},
		{
			name:      "superset_of combining an operand it cannot key",
			reference: "8.9",
			merge: func() error {
				_, err := SupersetOf{operatorValue: unusable()}.Merge(unusable())
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.merge()
			if err == nil {
				t.Skip("this operator accepted the operand, so there is no error to inspect")
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("[%s] the error carries a superior's operand: %v", tc.reference, err)
			}
		})
	}
}
