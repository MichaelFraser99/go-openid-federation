package model

import (
	"reflect"
	"testing"
)

func TestNewSupersetOf_NullIsHandled(t *testing.T) {
	_, err := NewSupersetOf([]any{})
	if err != nil {
		t.Errorf("no error expected, got %v", err)
	}

	_, err = NewSupersetOf(nil)
	if err == nil {
		t.Fatalf("NewSupersetOf should have returned an error")
	}
	if err.Error() != "operator value cannot be nil" {
		t.Errorf("expected \"operator value cannot be nil\", got %q", err.Error())
	}
}

func TestSupersetOf_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"resolve valid superset relationship with strings": {
			metadataParameterValue: []string{"foo", "bar", "baz", "qux"},
			operatorValue:          []string{"bar", "baz"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result, []string{"foo", "bar", "baz", "qux"}) {
					t.Errorf("expected result to be unchanged, got %v", result)
				}
			},
		},
		"resolve fails if metadata is not a superset (strings)": {
			metadataParameterValue: []string{"foo", "bar"},
			operatorValue:          []string{"baz", "qux"},
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				if err == nil {
					t.Error("expected error, but got none")
				}
				expectedError := "provided metadata is not a superset of the defined operator values"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
		"resolve valid superset relationship with numbers": {
			metadataParameterValue: []int{1, 2, 3, 4, 5},
			operatorValue:          []int{2, 3},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result, []int{1, 2, 3, 4, 5}) {
					t.Errorf("expected metadata to be unchanged, got %v", result)
				}
			},
		},
		"resolve fails if metadata is not a superset (numbers)": {
			metadataParameterValue: []int{1, 2},
			operatorValue:          []int{3, 4},
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				if err == nil {
					t.Error("expected error, but got none")
				}
				expectedError := "provided metadata is not a superset of the defined operator values"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
		"resolve valid superset relationship with objects": {
			metadataParameterValue: []map[string]any{
				{"id": 1, "value": "foo"},
				{"id": 2, "value": "bar"},
				{"id": 3, "value": "baz"},
			},
			operatorValue: []map[string]any{
				{"id": 2, "value": "bar"},
			},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result, []map[string]any{
					{"id": 1, "value": "foo"},
					{"id": 2, "value": "bar"},
					{"id": 3, "value": "baz"},
				}) {
					t.Errorf("expected metadata to be unchanged, got %v", result)
				}
			},
		},
		"resolve fails if metadata is not a superset (objects)": {
			metadataParameterValue: []map[string]any{
				{"id": 1, "value": "foo"},
			},
			operatorValue: []map[string]any{
				{"id": 2, "value": "bar"},
			},
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				if err == nil {
					t.Error("expected error, but got none")
				}
				expectedError := "provided metadata is not a superset of the defined operator values"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewSupersetOf(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

func TestSupersetOf_Merge(t *testing.T) {
	tests := map[string]struct {
		operatorValue, valueToMerge any
		validate                    func(t *testing.T, result MetadataPolicyOperator, err error)
	}{
		"successful MergePolicyOperators with superset relationship (string array)": {
			operatorValue: []string{"foo", "bar"},
			valueToMerge:  []string{"bar", "baz"},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{"bar", "baz", "foo"}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected merged result %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"successful MergePolicyOperators with superset relationship (int array)": {
			operatorValue: []int{1, 2},
			valueToMerge:  []int{2, 3},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{2, 3, 1}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected merged result %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"successful MergePolicyOperators with superset relationship (objects)": {
			operatorValue: []map[string]any{
				{"id": 1, "value": "foo"},
			},
			valueToMerge: []map[string]any{
				{"id": 2, "value": "bar"},
			},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{
					map[string]any{"id": 2, "value": "bar"},
					map[string]any{"id": 1, "value": "foo"},
				}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected merged result %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"MergePolicyOperators fails with differing input types": {
			operatorValue: []string{"foo", "bar"},
			valueToMerge:  []int{1, 2},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				if err == nil {
					t.Error("expected error, but got none")
				}
				expectedError := "elements of both slices must be of the same underlying type"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewSupersetOf(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.valueToMerge)
			tt.validate(t, result, err)
		})
	}
}
