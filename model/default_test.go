package model

import (
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestDefault_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"we can perform 'default' on a nil value with a default string": {
			metadataParameterValue: nil,
			operatorValue:          "foo-bar",
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
		"we can perform 'default' on a nil value with a default int": {
			metadataParameterValue: nil,
			operatorValue:          4,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(int) != 4 {
					t.Errorf("expected result to be '4', got %q", result)
				}
			},
		},
		"we can perform 'default' on a nil value with a default slice": {
			metadataParameterValue: nil,
			operatorValue:          []bool{true, false, true},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if !slices.Equal(result.([]bool), []bool{true, false, true}) {
					t.Errorf("expected result to be '[]bool{true, false, true}', got %q", result)
				}
			},
		},
		"we can perform 'default' on a nil value with a default map": {
			metadataParameterValue: nil,
			operatorValue:          map[string]any{"foo": "bar", "baz": "bang"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if !maps.Equal(result.(map[string]any), map[string]any{"foo": "bar", "baz": "bang"}) {
					t.Errorf("expected result to be 'map[string]any{\"foo\": \"bar\", \"baz\": \"bang\"}}', got %q", result)
				}
			},
		},
		"we can perform 'default' on an existing value with a default string": {
			metadataParameterValue: "bing-bang",
			operatorValue:          "foo-bar",
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(string) != "bing-bang" {
					t.Errorf("expected result to be 'bing-bang', got %q", result)
				}
			},
		},
		"we can perform 'default' on an existing value with a default int": {
			metadataParameterValue: "bing-bang",
			operatorValue:          4,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(string) != "bing-bang" {
					t.Errorf("expected result to be 'bing-bang', got %q", result)
				}
			},
		},
		"we can perform 'default' on an existing value with a default slice": {
			metadataParameterValue: "bing-bang",
			operatorValue:          []bool{true, false, true},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(string) != "bing-bang" {
					t.Errorf("expected result to be 'bing-bang', got %q", result)
				}
			},
		},
		"we can perform 'default' on an existing value with a default map": {
			metadataParameterValue: "bing-bang",
			operatorValue:          map[string]any{"foo": "bar", "baz": "bang"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(string) != "bing-bang" {
					t.Errorf("expected result to be 'bing-bang', got %q", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewDefault(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

func TestDefault_Merge(t *testing.T) {
	tests := map[string]struct {
		operatorValue, valueToMerge any
		validate                    func(t *testing.T, result MetadataPolicyOperator, err error)
	}{
		"successful MergePolicyOperators with deeply equal values": {
			operatorValue: "foo-bar",
			valueToMerge:  "foo-bar",
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result.OperatorValue() != "foo-bar" {
					t.Errorf("expected result to be 'foo-bar', got %q", result)
				}
			},
		},
		"MergePolicyOperators fails with different values": {
			operatorValue: "foo-bar",
			valueToMerge:  "baz-qux",
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				expectedError := "merging foo-bar and baz-qux not possible"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
				if result != nil {
					t.Errorf("expected result to be nil, got %q", result)
				}
			},
		},
		"MergePolicyOperators fails with valueToMerge nil": {
			operatorValue: "foo-bar",
			valueToMerge:  nil,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				expectedError := "merging foo-bar and <nil> not possible"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
				if result != nil {
					t.Errorf("expected result to be nil, got %q", result)
				}
			},
		},
		"MergePolicyOperators fails with different types": {
			operatorValue: "foo-bar",
			valueToMerge:  42,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				expectedError := "merging foo-bar and 42 not possible"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
				if result != nil {
					t.Errorf("expected result to be nil, got %q", result)
				}
			},
		},
		"MergePolicyOperators succeeds with deeply equal slices": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  []int{1, 2, 3},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(result.OperatorValue(), []int{1, 2, 3}) {
					t.Errorf("expected result to be []int{1, 2, 3}, got %v", result)
				}
			},
		},
		"MergePolicyOperators fails with different slices": {
			operatorValue: []int{1, 2, 3},
			valueToMerge:  []int{4, 5, 6},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				expectedError := "merging [1 2 3] and [4 5 6] not possible"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
				if result != nil {
					t.Errorf("expected result to be nil, got %v", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewDefault(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.valueToMerge)
			tt.validate(t, result, err)
		})
	}
}
