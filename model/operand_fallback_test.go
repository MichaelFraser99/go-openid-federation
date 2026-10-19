package model

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func invalidByte() string      { return string([]byte{0xff}) }
func otherInvalidByte() string { return string([]byte{0xfe}) }

func TestOperands_FallbackResolvesSubsetOf(t *testing.T) {
	tests := []struct {
		name     string
		operands []any
		metadata []any
		expect   []any
	}{
		{
			name:     "an invalid byte sequence the metadata also holds",
			operands: []any{invalidByte(), "a"},
			metadata: []any{invalidByte(), "b"},
			expect:   []any{invalidByte()},
		},
		{
			name:     "an invalid byte sequence the metadata does not hold",
			operands: []any{invalidByte()},
			metadata: []any{"b"},
			expect:   nil,
		},
		{
			name:     "an invalid byte sequence against a different one",
			operands: []any{invalidByte()},
			metadata: []any{otherInvalidByte()},
			expect:   nil,
		},
		{
			name:     "an infinity the metadata also holds",
			operands: []any{math.Inf(1), "a"},
			metadata: []any{math.Inf(1), "b"},
			expect:   []any{math.Inf(1)},
		},
		{
			name:     "an infinity against the opposite sign",
			operands: []any{math.Inf(1)},
			metadata: []any{math.Inf(-1)},
			expect:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewSubsetOf(test.operands)
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

func TestOperands_FallbackResolvesSupersetOf(t *testing.T) {
	tests := []struct {
		name      string
		operands  []any
		metadata  []any
		satisfied bool
	}{
		{
			name:      "an infinity the metadata holds",
			operands:  []any{math.Inf(1)},
			metadata:  []any{math.Inf(1), "x"},
			satisfied: true,
		},
		{
			name:     "an infinity the metadata does not hold",
			operands: []any{math.Inf(1)},
			metadata: []any{"x"},
		},
		{
			name:      "an invalid byte sequence the metadata holds",
			operands:  []any{invalidByte()},
			metadata:  []any{invalidByte(), "x"},
			satisfied: true,
		},
		{
			name:     "a valid string against an invalid byte sequence",
			operands: []any{"a"},
			metadata: []any{invalidByte()},
		},
		{
			name:     "an invalid byte sequence against a different one",
			operands: []any{invalidByte()},
			metadata: []any{otherInvalidByte()},
		},
		{
			name:     "a NaN can satisfy nothing, not even itself",
			operands: []any{math.NaN()},
			metadata: []any{math.NaN()},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewSupersetOf(test.operands)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}
			_, err = operator.Resolve(test.metadata)
			if test.satisfied && err != nil {
				t.Errorf("expected the requirement to be satisfied, got error: %v", err)
			}
			if !test.satisfied && err == nil {
				t.Error("expected the requirement to be refused")
			}
		})
	}
}

func TestOperands_FallbackMerges(t *testing.T) {
	tests := []struct {
		name  string
		first any
		other any
		merge bool
	}{
		{name: "the same invalid byte sequence", first: invalidByte(), other: invalidByte(), merge: true},
		{name: "two different invalid byte sequences", first: invalidByte(), other: otherInvalidByte()},
		{name: "the same infinity", first: math.Inf(1), other: math.Inf(1), merge: true},
		{name: "opposite infinities", first: math.Inf(1), other: math.Inf(-1)},
		{name: "a NaN against itself", first: math.NaN(), other: math.NaN()},
		{name: "an invalid byte sequence against the replacement character", first: invalidByte(), other: "�"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, operator := range []struct {
				name  string
				build func(any) (MetadataPolicyOperator, error)
			}{
				{name: "value", build: func(v any) (MetadataPolicyOperator, error) { return NewValue(v) }},
				{name: "default", build: func(v any) (MetadataPolicyOperator, error) { return NewDefault(v) }},
			} {
				t.Run(operator.name, func(t *testing.T) {
					built, err := operator.build(test.first)
					if err != nil {
						t.Fatalf("no error expected building the operator, got: %v", err)
					}
					_, err = built.Merge(test.other)
					if test.merge && err != nil {
						t.Errorf("expected the two operands to merge, got error: %v", err)
					}
					if !test.merge && err == nil {
						t.Error("expected the merge to be refused")
					}
				})
			}
		})
	}
}

func TestOperands_EqualityIsDefinedForDecodedShapes(t *testing.T) {
	tests := []struct {
		name  string
		first any
		other any
		same  bool
	}{
		{
			name:  "two structs whose only difference is in unexported fields",
			first: struct{ secret string }{"a"},
			other: struct{ secret string }{"b"},
		},
		{
			name:  "a struct against the object its JSON form renders",
			first: struct{ secret string }{"a"},
			other: map[string]any{},
		},
		{
			name:  "a Go float slice holding zero against one holding negative zero",
			first: []float64{0},
			other: []float64{math.Copysign(0, -1)},
			same:  true,
		},
		{
			name:  "a Go string map against the decoded object with the same members",
			first: map[string]string{"a": "b"},
			other: map[string]any{"a": "b"},
		},
		{
			name:  "a typed container holding an invalid byte sequence",
			first: []map[string]any{{"a": invalidByte()}},
			other: []map[string]any{{"a": otherInvalidByte()}},
		},
		{
			name:  "a nil Go string slice against a nil decoded array",
			first: []string(nil),
			other: []any(nil),
		},
		{
			name:  "a nil decoded array against a nil decoded object",
			first: []any(nil),
			other: map[string]any(nil),
			same:  true,
		},
		{
			name:  "a nil decoded array against an empty one",
			first: []any(nil),
			other: []any{},
		},
		{
			name:  "two JSON numbers written differently",
			first: json.Number("1e2"),
			other: json.Number("100"),
		},
		{
			name:  "a JSON number against the float it denotes",
			first: json.Number("100"),
			other: float64(100),
		},
		{
			name:  "a 32-bit float against the 64-bit float printed alike",
			first: float32(0.1),
			other: float64(0.1),
		},
		{
			name:  "a Go integer against the float holding the same integer",
			first: int(1),
			other: float64(1),
			same:  true,
		},
		{
			name:  "a Go integer a float64 cannot hold exactly",
			first: int64(1<<53) + 1,
			other: float64(1 << 53),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := containsOperand([]any{test.first}, test.other); got != test.same {
				t.Errorf("expected membership %v, got %v", test.same, got)
			}
			expect := 1
			if !test.same {
				expect = 2
			}
			if got := DeduplicateSlice([]any{test.first, test.other}); len(got) != expect {
				t.Errorf("expected %d value(s) after deduplication, got %d", expect, len(got))
			}
		})
	}
}

func TestOperands_NaNInsideAContainerNeverMatches(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "a bare NaN", value: math.NaN()},
		{name: "an array holding a NaN", value: []any{math.NaN()}},
		{name: "an object holding a NaN", value: map[string]any{"a": math.NaN()}},
		{name: "a nested object holding a NaN", value: map[string]any{"a": map[string]any{"b": math.NaN()}}},
		{name: "a Go float slice holding a NaN", value: []float64{math.NaN()}},
		{name: "a struct holding a NaN", value: struct{ A float64 }{math.NaN()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if operandCanMatch(test.value) {
				t.Error("a value holding a NaN can match nothing, not even itself")
			}
			if containsOperand([]any{test.value}, test.value) {
				t.Error("a value holding a NaN must not be a member of a set holding it")
			}
			set := newOperandSet([]any{test.value, test.value})
			if set.fallbackCount() != 0 {
				t.Errorf("a value that can match nothing must not enter the fallback bucket, got %d entries", set.fallbackCount())
			}
		})
	}
}

func TestOperands_ValuesThatCanMatchThemselves(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "an infinity", value: math.Inf(1)},
		{name: "an invalid byte sequence", value: invalidByte()},
		{name: "a struct holding a finite float", value: struct{ A float64 }{1}},
		{name: "a channel", value: make(chan int)},
		{name: "a nil function", value: (func())(nil)},
	}

	unmatchable := []struct {
		name  string
		value any
	}{
		{name: "a function", value: func() {}},
		{name: "a struct holding a function", value: struct{ A func() }{func() {}}},
	}

	for _, test := range unmatchable {
		t.Run(test.name, func(t *testing.T) {
			if operandCanMatch(test.value) {
				t.Error("a function is equal to nothing, not even itself, so it must not be able to match")
			}
			if containsOperand([]any{test.value}, test.value) {
				t.Error("a value equal to nothing must not be a member of a set holding it")
			}
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !operandCanMatch(test.value) {
				t.Error("this value is equal to itself, so it must be able to match")
			}
			if !containsOperand([]any{test.value}, test.value) {
				t.Error("a value equal to itself must be a member of a set holding it")
			}
		})
	}
}
