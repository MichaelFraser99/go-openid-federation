package model

import (
	"reflect"
	"slices"
	"testing"
)

func TestNewSubsetOf_NullIsHandled(t *testing.T) {
	_, err := NewSubsetOf([]any{})
	if err != nil {
		t.Errorf("no error expected, got %v", err)
	}

	_, err = NewSubsetOf(nil)
	if err == nil {
		t.Fatalf("NewSubsetOf should have returned an error")
	}
	if err.Error() != "operator value cannot be nil" {
		t.Errorf("expected \"operator value cannot be nil\", got %q", err.Error())
	}
}

func TestSubsetOf_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"intersection with common elements (string)": {
			metadataParameterValue: []string{"foo", "bar", "baz"},
			operatorValue:          []string{"bar", "qux", "foo"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{"foo", "bar"}
				if !reflect.DeepEqual(result, expected) {
					t.Errorf("expected result %v, got %v", expected, result)
				}
			},
		},
		"no common elements results in empty slice": {
			metadataParameterValue: []string{"foo", "bar", "baz"},
			operatorValue:          []string{"qux", "quux"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatalf("expected non-nil result")
				}
				if _, ok := result.([]any); !ok {
					t.Fatalf("expected result to be of type []any, got %T", result)
				}
				if !slices.Equal(result.([]any), []any{}) {
					t.Errorf("expected an empty slice, got %v", result)
				}
			},
		},
		"metadata is nil leads to removal": {
			metadataParameterValue: nil,
			operatorValue:          []string{"foo", "bar"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
			},
		},
		"intersection with common elements (numbers)": {
			metadataParameterValue: []int{1, 2, 3},
			operatorValue:          []int{2, 3, 4},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{2, 3}
				if !reflect.DeepEqual(result, expected) {
					t.Errorf("expected result %v, got %v", expected, result)
				}
			},
		},
		"no common elements (numbers)": {
			metadataParameterValue: []int{5, 6, 7},
			operatorValue:          []int{8, 9},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatalf("expected non-nil result")
				}
				if _, ok := result.([]any); !ok {
					t.Fatalf("expected result to be of type []any, got %T", result)
				}
				if !slices.Equal(result.([]any), []any{}) {
					t.Errorf("expected an empty slice, got %v", result)
				}
			},
		},
		"intersection with common elements (objects)": {
			metadataParameterValue: []map[string]any{
				{"id": 1, "value": "foo"},
				{"id": 2, "value": "bar"},
				{"id": 3, "value": "baz"},
			},
			operatorValue: []map[string]any{
				{"id": 2, "value": "bar"},
				{"id": 4, "value": "qux"},
				{"id": 1, "value": "foo"},
			},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{
					map[string]any{"id": 1, "value": "foo"},
					map[string]any{"id": 2, "value": "bar"},
				}
				if !reflect.DeepEqual(result, expected) {
					t.Errorf("expected result %v, got %v", expected, result)
				}
			},
		},
		"no common elements (objects)": {
			metadataParameterValue: []map[string]any{
				{"id": 5, "value": "quux"},
				{"id": 6, "value": "corge"},
			},
			operatorValue: []map[string]any{
				{"id": 7, "value": "grault"},
				{"id": 8, "value": "garply"},
			},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatalf("expected non-nil result")
				}
				if _, ok := result.([]any); !ok {
					t.Fatalf("expected result to be of type []any, got %T", result)
				}
				if !slices.Equal(result.([]any), []any{}) {
					t.Errorf("expected an empty slice, got %v", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewSubsetOf(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

func TestSubsetOf_Merge(t *testing.T) {
	tests := map[string]struct {
		operatorValue, valueToMerge any
		validate                    func(t *testing.T, result MetadataPolicyOperator, err error)
	}{
		"successful MergePolicyOperators with intersection (strings)": {
			operatorValue: []string{"foo", "bar", "baz"},
			valueToMerge:  []string{"bar", "baz", "qux"},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{"bar", "baz"}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected merged result %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"successful MergePolicyOperators with empty intersection": {
			operatorValue: []string{"foo", "bar"},
			valueToMerge:  []string{"qux", "quux"},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result.OperatorValue(), []any{}) {
					t.Errorf("expected merged result %v, got %v", []any{}, result.OperatorValue())
				}
			},
		},

		"successful MergePolicyOperators with intersection (numbers)": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  []int{2, 3, 4},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{2, 3}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected merged result %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"successful MergePolicyOperators with empty intersection (numbers)": {
			operatorValue: []int{5, 6},
			valueToMerge:  []int{7, 8},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result.OperatorValue(), []any{}) {
					t.Errorf("expected merged result %v, got %v", []any{}, result.OperatorValue())
				}
			},
		},
		"successful MergePolicyOperators with intersection (objects)": {
			operatorValue: []map[string]any{
				{"id": 1, "value": "foo"},
				{"id": 2, "value": "bar"},
			},
			valueToMerge: []map[string]any{
				{"id": 2, "value": "bar"},
				{"id": 3, "value": "baz"},
			},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{
					map[string]any{"id": 2, "value": "bar"},
				}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected merged result %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"successful MergePolicyOperators with empty intersection (objects)": {
			operatorValue: []map[string]any{
				{"id": 4, "value": "corge"},
				{"id": 5, "value": "grault"},
			},
			valueToMerge: []map[string]any{
				{"id": 6, "value": "garply"},
				{"id": 7, "value": "waldo"},
			},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result.OperatorValue(), []any{}) {
					t.Errorf("expected merged result %v, got %v", []any{}, result.OperatorValue())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewSubsetOf(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.valueToMerge)
			tt.validate(t, result, err)
		})
	}
}
