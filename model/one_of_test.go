package model

import (
	"reflect"
	"testing"
)

func TestNewOneOf_NullIsHandled(t *testing.T) {
	_, err := NewOneOf([]any{})
	if err != nil {
		t.Errorf("no error expected, got %v", err)
	}

	_, err = NewOneOf(nil)
	if err == nil {
		t.Fatalf("NewOneOf should have returned an error")
	}
	if err.Error() != "operator value cannot be nil" {
		t.Errorf("expected \"operator value cannot be nil\", got %q", err.Error())
	}
}

func TestOneOf_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"happy path string match": {
			metadataParameterValue: "foo-bar",
			operatorValue:          []string{"foo-bar", "bar-baz"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(string) != "foo-bar" {
					t.Errorf("expected result to be 'foo-bar', got %q", result)
				}
			},
		},
		"unhappy path string mismatch": {
			metadataParameterValue: "foo-bar",
			operatorValue:          []string{"bin-bong", "bar-baz"},
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "metadata parameter value foo-bar is not one of the allowed values"
				if err.Error() != expectedError {
					t.Errorf("expected error, got %q", err.Error())
				}
			},
		},
		"happy path map[string]any match": {
			metadataParameterValue: map[string]any{"key": "value"},
			operatorValue:          []map[string]any{{"key": "value"}, {"another": "map"}},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if !reflect.DeepEqual(result, map[string]any{"key": "value"}) {
					t.Errorf("expected result to be map[key:value], got %v", result)
				}
			},
		},
		"unhappy path map[string]any mismatch": {
			metadataParameterValue: map[string]any{"key": "value"},
			operatorValue:          []map[string]any{{"another": "map"}},
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "metadata parameter value map[key:value] is not one of the allowed values"
				if err.Error() != expectedError {
					t.Errorf("expected error, got %q", err.Error())
				}
			},
		},
		"happy path number match": {
			metadataParameterValue: 42,
			operatorValue:          []int{42, 23},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(int) != 42 {
					t.Errorf("expected result to be 42, got %v", result)
				}
			},
		},
		"unhappy path number mismatch": {
			metadataParameterValue: 42,
			operatorValue:          []int{23, 56},
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "metadata parameter value 42 is not one of the allowed values"
				if err.Error() != expectedError {
					t.Errorf("expected error, got %q", err.Error())
				}
			},
		},
		"happy path with nil metadataParameterValue": {
			metadataParameterValue: nil,
			operatorValue:          []string{"foo-bar", "bar-baz"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != nil {
					t.Fatalf("expected result to be nil, got %v", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewOneOf(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

func TestOneOf_Merge(t *testing.T) {
	tests := map[string]struct {
		operatorValue, valueToMerge any
		validate                    func(t *testing.T, result MetadataPolicyOperator, err error)
	}{
		"slices with intersection": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  []int{3, 4, 5},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{3}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected result to be %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"slices with no intersection": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  []int{4, 5, 6},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "intersection of operator values is empty"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
		"operator slice empty": {
			operatorValue: []int{},
			valueToMerge:  []int{1, 2, 3},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "intersection of operator values is empty"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
		"MergePolicyOperators slice empty": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  []int{},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "intersection of operator values is empty"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
		"MergePolicyOperators value nil": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  nil,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				expected := []any{1, 2, 3}
				if !reflect.DeepEqual(result.OperatorValue(), expected) {
					t.Errorf("expected result to be %v, got %v", expected, result.OperatorValue())
				}
			},
		},
		"incompatible types (MergePolicyOperators not slice)": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  42,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if result != nil {
					t.Fatal("expected result to be nil")
				}
				if err == nil {
					t.Fatal("expected error")
				}
				expectedError := "both operator values must be slices"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewOneOf(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.valueToMerge)
			tt.validate(t, result, err)
		})
	}
}
