package model

import (
	"reflect"
	"slices"
	"testing"
)

func TestValue_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"we can resolve two like strings": {
			metadataParameterValue: "foo-bar",
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
		"we can resolve two different strings": {
			metadataParameterValue: "foo-bar",
			operatorValue:          "foo-bar-baz",
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(string) != "foo-bar-baz" {
					t.Errorf("expected result to be 'foo-bar-baz', got %q", result)
				}
			},
		},
		"we can resolve two like numbers": {
			metadataParameterValue: 123,
			operatorValue:          123,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(int) != 123 {
					t.Errorf("expected result to be '123', got %q", result)
				}
			},
		},
		"we can resolve two like floating point numbers": {
			metadataParameterValue: 123.456,
			operatorValue:          123.456,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(float64) != 123.456 {
					t.Errorf("expected result to be '123.456', got %q", result)
				}
			},
		},
		"we can resolve two different numbers": {
			metadataParameterValue: 123,
			operatorValue:          234,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(int) != 234 {
					t.Errorf("expected result to be '234', got %q", result)
				}
			},
		},
		"we can resolve two like booleans": {
			metadataParameterValue: true,
			operatorValue:          true,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(bool) != true {
					t.Errorf("expected result to be 'foo-bar', got %q", result)
				}
			},
		},
		"we can resolve two different booleans": {
			metadataParameterValue: true,
			operatorValue:          false,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if result.(bool) != false {
					t.Errorf("expected result to be 'false', got %q", result)
				}
			},
		},
		"we can resolve two like slices": {
			metadataParameterValue: []string{"foo-bar", "bar-baz"},
			operatorValue:          []string{"foo-bar", "bar-baz"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.([]string)) != 2 {
					t.Errorf("expected result to be length 2, got %d", len(result.([]string)))
				}
				for _, v := range []string{"foo-bar", "bar-baz"} {
					if !slices.Contains(result.([]string), v) {
						t.Errorf("expected result to contain '%s', got %q", v, result)
					}
				}
			},
		},
		"we can resolve two like slices with different order": {
			metadataParameterValue: []string{"foo-bar", "bar-baz"},
			operatorValue:          []string{"bar-baz", "foo-bar"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}

				if len(result.([]string)) != 2 {
					t.Errorf("expected result to be length 2, got %d", len(result.([]string)))
				}
				for _, v := range []string{"foo-bar", "bar-baz"} {
					if !slices.Contains(result.([]string), v) {
						t.Errorf("expected result to contain '%s', got %q", v, result)
					}
				}
			},
		},
		"we can resolve two different slices": {
			metadataParameterValue: []string{"foo-bar", "bar-baz"},
			operatorValue:          []string{"foo-bar", "bar-baz", "baz-bin"},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}

				if len(result.([]string)) != 3 {
					t.Errorf("expected result to be length 3, got %d", len(result.([]string)))
				}
				for _, v := range []string{"foo-bar", "bar-baz", "baz-bin"} {
					if !slices.Contains(result.([]string), v) {
						t.Errorf("expected result to contain '%s', got %q", v, result)
					}
				}
			},
		},
		"resolve succeeds when metadataParameterValue is nil": {
			metadataParameterValue: nil,
			operatorValue:          "foo-bar",
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != "foo-bar" {
					t.Errorf("expected result to be 'foo-bar', got %q", result)
				}
			},
		},
		"resolve succeeds when both values are nil": {
			metadataParameterValue: nil,
			operatorValue:          nil,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != nil {
					t.Errorf("expected result to be nil, got %q", result)
				}
			},
		},
		"resolve fails on type mismatch": {
			metadataParameterValue: 123,
			operatorValue:          "foo-bar",
			validate: func(t *testing.T, result any, err error) {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				expectedError := "type mismatch: metadata parameter value is of type int, but operator value is of type string"
				if err.Error() != expectedError {
					t.Errorf("expected error %q, got %q", expectedError, err.Error())
				}
			},
		},
		"resolve succeeds for empty slices": {
			metadataParameterValue: []string{},
			operatorValue:          []string{},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if len(result.([]string)) != 0 {
					t.Errorf("expected result to be an empty slice, got %v", result)
				}
			},
		},
		"we can resolve two like objects": {
			metadataParameterValue: map[string]any{
				"foo": "bar",
				"bar": map[string]string{
					"baz": "bin",
				},
			},
			operatorValue: map[string]any{
				"foo": "bar",
				"bar": map[string]string{
					"baz": "bin",
				},
			},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if !reflect.DeepEqual(result.(map[string]any), map[string]any{
					"foo": "bar",
					"bar": map[string]string{
						"baz": "bin",
					},
				}) {
					t.Errorf("expected result to be '%v', got %q", map[string]any{
						"foo": "bar",
						"bar": map[string]string{
							"baz": "bin",
						},
					}, result)
				}
			},
		},
		"we can resolve two different objects": {
			metadataParameterValue: map[string]any{
				"bin": "bar",
				"bong": map[string]string{
					"biz": "bal",
				},
			},
			operatorValue: map[string]any{
				"foo": "bar",
				"bar": map[string]string{
					"baz": "bin",
				},
			},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if !reflect.DeepEqual(result.(map[string]any), map[string]any{
					"foo": "bar",
					"bar": map[string]string{
						"baz": "bin",
					},
				}) {
					t.Errorf("expected result to be '%v', got %q", map[string]any{
						"foo": "bar",
						"bar": map[string]string{
							"baz": "bin",
						},
					}, result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewValue(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

func TestValue_Merge(t *testing.T) {
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
		"MergePolicyOperators fails with operatorValue nil": {
			operatorValue: nil,
			valueToMerge:  "foo-bar",
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				expectedError := "merging <nil> and foo-bar not possible"
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
			operator, err := NewValue(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.valueToMerge)
			tt.validate(t, result, err)
		})
	}
}
