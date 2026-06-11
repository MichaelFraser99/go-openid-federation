package model

import (
	"reflect"
	"testing"
)

func TestDeduplicateSlice(t *testing.T) {
	tests := map[string]struct {
		input    []any
		expected []any
	}{
		"empty slice": {
			input:    []any{},
			expected: []any{},
		},
		"string duplicates": {
			input:    []any{"a", "b", "a", "c", "b", "d"},
			expected: []any{"a", "b", "c", "d"},
		},
		"int duplicates": {
			input:    []any{1, 2, 1, 3, 2, 4},
			expected: []any{1, 2, 3, 4},
		},
		"float duplicates": {
			input:    []any{1.5, 2.5, 1.5, 3.5},
			expected: []any{1.5, 2.5, 3.5},
		},
		"bool duplicates": {
			input:    []any{true, false, true, false, true},
			expected: []any{true, false},
		},
		"mixed type primitives": {
			input:    []any{"a", 1, "a", 2, 1, "b"},
			expected: []any{"a", 1, 2, "b"},
		},
		"map duplicates": {
			input: []any{
				map[string]any{"x": 1, "y": 2},
				map[string]any{"a": 3, "b": 4},
				map[string]any{"y": 2, "x": 1}, // Same as first but different order
				map[string]any{"b": 4, "a": 3}, // Same as second but different order
			},
			expected: []any{
				map[string]any{"x": 1, "y": 2},
				map[string]any{"a": 3, "b": 4},
			},
		},
		"no duplicates": {
			input:    []any{1, 2, 3, 4, 5},
			expected: []any{1, 2, 3, 4, 5},
		},
		"all duplicates": {
			input:    []any{"x", "x", "x", "x"},
			expected: []any{"x"},
		},
		"preserves order": {
			input:    []any{"z", "a", "m", "b", "a", "z"},
			expected: []any{"z", "a", "m", "b"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := DeduplicateSlice(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeduplicateSlice() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewAdd_Deduplication(t *testing.T) {
	tests := map[string]struct {
		input    any
		expected []any
	}{
		"string duplicates": {
			input:    []string{"a", "b", "a", "c"},
			expected: []any{"a", "b", "c"},
		},
		"int duplicates": {
			input:    []int{1, 2, 1, 3},
			expected: []any{1, 2, 3},
		},
		"mixed int types": {
			input:    []any{1, 2, 1, 3, 2},
			expected: []any{1, 2, 3},
		},
		"no duplicates": {
			input:    []string{"a", "b", "c"},
			expected: []any{"a", "b", "c"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewAdd(tt.input)
			if err != nil {
				t.Fatalf("NewAdd() error = %v", err)
			}
			if !reflect.DeepEqual(result.operatorValue, tt.expected) {
				t.Errorf("NewAdd() operatorValue = %v, want %v", result.operatorValue, tt.expected)
			}
		})
	}
}

func TestNewOneOf_Deduplication(t *testing.T) {
	tests := map[string]struct {
		input    any
		expected []any
	}{
		"string duplicates": {
			input:    []string{"option1", "option2", "option1", "option3"},
			expected: []any{"option1", "option2", "option3"},
		},
		"int duplicates": {
			input:    []int{10, 20, 10, 30},
			expected: []any{10, 20, 30},
		},
		"no duplicates": {
			input:    []string{"a", "b", "c"},
			expected: []any{"a", "b", "c"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewOneOf(tt.input)
			if err != nil {
				t.Fatalf("NewOneOf() error = %v", err)
			}
			if !reflect.DeepEqual(result.operatorValue, tt.expected) {
				t.Errorf("NewOneOf() operatorValue = %v, want %v", result.operatorValue, tt.expected)
			}
		})
	}
}

func TestNewSubsetOf_Deduplication(t *testing.T) {
	tests := map[string]struct {
		input    any
		expected []any
	}{
		"string duplicates": {
			input:    []string{"scope1", "scope2", "scope1", "scope3"},
			expected: []any{"scope1", "scope2", "scope3"},
		},
		"int duplicates": {
			input:    []int{5, 10, 5, 15},
			expected: []any{5, 10, 15},
		},
		"float duplicates": {
			input:    []float64{1.1, 2.2, 1.1, 3.3},
			expected: []any{1.1, 2.2, 3.3},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewSubsetOf(tt.input)
			if err != nil {
				t.Fatalf("NewSubsetOf() error = %v", err)
			}
			if !reflect.DeepEqual(result.operatorValue, tt.expected) {
				t.Errorf("NewSubsetOf() operatorValue = %v, want %v", result.operatorValue, tt.expected)
			}
		})
	}
}

func TestNewSupersetOf_Deduplication(t *testing.T) {
	tests := map[string]struct {
		input    any
		expected []any
	}{
		"string duplicates": {
			input:    []string{"required1", "required2", "required1"},
			expected: []any{"required1", "required2"},
		},
		"map duplicates": {
			input: []any{
				map[string]any{"key": "value1"},
				map[string]any{"key": "value2"},
				map[string]any{"key": "value1"}, // Duplicate
			},
			expected: []any{
				map[string]any{"key": "value1"},
				map[string]any{"key": "value2"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewSupersetOf(tt.input)
			if err != nil {
				t.Fatalf("NewSupersetOf() error = %v", err)
			}
			if !reflect.DeepEqual(result.operatorValue, tt.expected) {
				t.Errorf("NewSupersetOf() operatorValue = %v, want %v", result.operatorValue, tt.expected)
			}
		})
	}
}

func TestNewValue_Deduplication(t *testing.T) {
	tests := map[string]struct {
		input    any
		expected any
	}{
		"string slice with duplicates": {
			input:    []string{"a", "b", "a", "c"},
			expected: []any{"a", "b", "c"},
		},
		"int slice with duplicates": {
			input:    []int{1, 2, 1, 3},
			expected: []any{1, 2, 3},
		},
		"non-slice value": {
			input:    "single_value",
			expected: "single_value",
		},
		"int value": {
			input:    42,
			expected: 42,
		},
		"bool value": {
			input:    true,
			expected: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewValue(tt.input)
			if err != nil {
				t.Fatalf("NewValue() error = %v", err)
			}
			if !reflect.DeepEqual(result.operatorValue, tt.expected) {
				t.Errorf("NewValue() operatorValue = %v, want %v", result.operatorValue, tt.expected)
			}
		})
	}
}

func TestNewDefault_Deduplication(t *testing.T) {
	tests := map[string]struct {
		input    any
		expected any
	}{
		"string slice with duplicates": {
			input:    []string{"default1", "default2", "default1"},
			expected: []any{"default1", "default2"},
		},
		"int slice with duplicates": {
			input:    []int{100, 200, 100, 300},
			expected: []any{100, 200, 300},
		},
		"non-slice value": {
			input:    "default_value",
			expected: "default_value",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewDefault(tt.input)
			if err != nil {
				t.Fatalf("NewDefault() error = %v", err)
			}
			if !reflect.DeepEqual(result.operatorValue, tt.expected) {
				t.Errorf("NewDefault() operatorValue = %v, want %v", result.operatorValue, tt.expected)
			}
		})
	}
}

// Test that deduplication works with complex map structures
func TestDeduplication_ComplexMaps(t *testing.T) {
	input := []any{
		map[string]any{"x": 1, "y": 2, "z": 3},
		map[string]any{"a": "hello", "b": "world"},
		map[string]any{"y": 2, "z": 3, "x": 1}, // Same as first, different order
		map[string]any{"b": "world", "a": "hello"}, // Same as second, different order
		map[string]any{"x": 1, "y": 2, "z": 4}, // Different from first
	}

	expected := []any{
		map[string]any{"x": 1, "y": 2, "z": 3},
		map[string]any{"a": "hello", "b": "world"},
		map[string]any{"x": 1, "y": 2, "z": 4},
	}

	result := DeduplicateSlice(input)
	if len(result) != len(expected) {
		t.Fatalf("DeduplicateSlice() length = %d, want %d", len(result), len(expected))
	}

	for i := range expected {
		if !reflect.DeepEqual(result[i], expected[i]) {
			t.Errorf("DeduplicateSlice()[%d] = %v, want %v", i, result[i], expected[i])
		}
	}
}

// Test edge cases
func TestDeduplication_EdgeCases(t *testing.T) {
	t.Run("single element", func(t *testing.T) {
		input := []any{"single"}
		expected := []any{"single"}
		result := DeduplicateSlice(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("DeduplicateSlice() = %v, want %v", result, expected)
		}
	})

	t.Run("two identical elements", func(t *testing.T) {
		input := []any{"same", "same"}
		expected := []any{"same"}
		result := DeduplicateSlice(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("DeduplicateSlice() = %v, want %v", result, expected)
		}
	})

	t.Run("nil values in slice", func(t *testing.T) {
		input := []any{"a", nil, "b", nil, "c"}
		expected := []any{"a", nil, "b", "c"}
		result := DeduplicateSlice(input)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("DeduplicateSlice() = %v, want %v", result, expected)
		}
	})
}

// Test that all data types work correctly
func TestDeduplication_AllDataTypes(t *testing.T) {
	tests := map[string]struct {
		operator     string
		createFunc   func(any) (any, error)
		input        any
		expectedLen  int
	}{
		"Add with int8": {
			operator: "add",
			createFunc: func(v any) (any, error) {
				op, err := NewAdd(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []int8{1, 2, 1, 3, 2},
			expectedLen: 3,
		},
		"Add with int16": {
			operator: "add",
			createFunc: func(v any) (any, error) {
				op, err := NewAdd(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []int16{100, 200, 100, 300},
			expectedLen: 3,
		},
		"Add with int32": {
			operator: "add",
			createFunc: func(v any) (any, error) {
				op, err := NewAdd(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []int32{1000, 2000, 1000, 3000},
			expectedLen: 3,
		},
		"Add with int64": {
			operator: "add",
			createFunc: func(v any) (any, error) {
				op, err := NewAdd(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []int64{10000, 20000, 10000, 30000},
			expectedLen: 3,
		},
		"Add with uint": {
			operator: "add",
			createFunc: func(v any) (any, error) {
				op, err := NewAdd(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []uint{1, 2, 1, 3},
			expectedLen: 3,
		},
		"Add with float32": {
			operator: "add",
			createFunc: func(v any) (any, error) {
				op, err := NewAdd(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []float32{1.1, 2.2, 1.1, 3.3},
			expectedLen: 3,
		},
		"OneOf with mixed types": {
			operator: "one_of",
			createFunc: func(v any) (any, error) {
				op, err := NewOneOf(v)
				if err != nil {
					return nil, err
				}
				return op.operatorValue, nil
			},
			input:       []any{"a", 1, "a", 2, 1},
			expectedLen: 3,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tt.createFunc(tt.input)
			if err != nil {
				t.Fatalf("%s creation error = %v", tt.operator, err)
			}
			resultSlice, ok := result.([]any)
			if !ok {
				t.Fatalf("result is not []any, got %T", result)
			}
			if len(resultSlice) != tt.expectedLen {
				t.Errorf("result length = %d, want %d. Result: %v", len(resultSlice), tt.expectedLen, resultSlice)
			}
		})
	}
}
