package model

import (
	"reflect"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewAdd_NullIsHandled(t *testing.T) {
	_, err := NewAdd([]any{})
	if err != nil {
		t.Errorf("no error expected, got %v", err)
	}

	_, err = NewAdd(nil)
	if err == nil {
		t.Fatalf("NewAdd should have returned an error")
	}
	if err.Error() != "operator value cannot be nil" {
		t.Errorf("expected \"operator value cannot be nil\", got %q", err.Error())
	}
}

func TestAdd_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"we can perform 'add' on two string slices": {
			metadataParameterValue: []string{"foo-bar"},
			operatorValue:          []string{"bar-baz"},
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
				if !slices.Contains(result.([]string), "foo-bar") {
					t.Errorf("expected result to contain 'foo-bar', got %q", result)
				}
				if !slices.Contains(result.([]string), "bar-baz") {
					t.Errorf("expected result to contain 'bar-baz', got %q", result)
				}
			},
		},
		"we can perform 'add' on two object slices": {
			metadataParameterValue: []map[string]any{
				{
					"foo": "bar",
					"baz": []string{"bin", "bang"},
				},
			},
			operatorValue: []map[string]any{
				{
					"foo": "bar",
					"baz": []string{"bin", "bang"},
				},
				{
					"bin":  "bar",
					"bong": []string{"bin", "bang"},
				},
			},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.([]map[string]any)) != 2 {
					t.Errorf("expected result to be length 2, got %d", len(result.([]map[string]any)))
				}
				if !reflect.DeepEqual(result.([]map[string]any),
					[]map[string]any{
						{
							"foo": "bar",
							"baz": []string{"bin", "bang"},
						},
						{
							"bin":  "bar",
							"bong": []string{"bin", "bang"},
						},
					}) {
					t.Errorf("expected result to be '%v', got %q", []map[string]any{

						{
							"foo": "bar",
							"baz": []string{"bin", "bang"},
						},
						{
							"bin":  "bar",
							"bong": []string{"bin", "bang"},
						},
					}, result)
				}
			},
		},
		"we can perform 'add' on two integer slices": {
			metadataParameterValue: []int{1, 2, 3},
			operatorValue:          []int{2, 3, 4},
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.([]int)) != 4 {
					t.Errorf("expected result to be length 4, got %d", len(result.([]int)))
				}
				if !slices.Contains(result.([]int), 1) {
					t.Errorf("expected result to contain '1', got %q", result)
				}
				if !slices.Contains(result.([]int), 2) {
					t.Errorf("expected result to contain '2', got %q", result)
				}
				if !slices.Contains(result.([]int), 3) {
					t.Errorf("expected result to contain '3', got %q", result)
				}
				if !slices.Contains(result.([]int), 4) {
					t.Errorf("expected result to contain '4', got %q", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewAdd(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

func TestAdd_Merge(t *testing.T) {
	tests := map[string]struct {
		operatorValue1, operatorValue2 any
		validate                       func(t *testing.T, result MetadataPolicyOperator, err error)
	}{
		"we can MergePolicyOperators two string slices": {
			operatorValue1: []string{"foo-bar", "bar-baz"},
			operatorValue2: []string{"bar-baz", "baz-bang"},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.OperatorValue().([]any)) != 3 {
					t.Errorf("expected result to be length 3, got %d", len(result.OperatorValue().([]any)))
				}
				if !slices.Contains(result.OperatorValue().([]any), "foo-bar") {
					t.Errorf("expected result to contain 'foo-bar', got %q", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), "bar-baz") {
					t.Errorf("expected result to contain 'bar-baz', got %q", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), "baz-bang") {
					t.Errorf("expected result to contain 'baz-bang', got %q", result)
				}
			},
		},
		"we can MergePolicyOperators two integer slices": {
			operatorValue1: []int{1, 2, 3},
			operatorValue2: []int{2, 3, 4},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.OperatorValue().([]any)) != 4 {
					t.Errorf("expected result to be length 4, got %d", len(result.OperatorValue().([]any)))
				}
				if !slices.Contains(result.OperatorValue().([]any), 1) {
					t.Errorf("expected result to contain '1', got %q", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), 2) {
					t.Errorf("expected result to contain '2', got %q", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), 3) {
					t.Errorf("expected result to contain '3', got %q", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), 4) {
					t.Errorf("expected result to contain '4', got %q", result)
				}
			},
		},
		"we can MergePolicyOperators two map slices": {
			operatorValue1: []map[string]any{
				{
					"foo": "bar",
				},
			},
			operatorValue2: []map[string]any{
				{
					"baz": "bang",
				},
			},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.OperatorValue().([]any)) != 2 {
					t.Errorf("expected result to be length 2, got %d", len(result.OperatorValue().([]any)))
				}
			},
		},
		"we can MergePolicyOperators two float slices": {
			operatorValue1: []float64{1.1, 2.2, 3.3},
			operatorValue2: []float64{2.2, 3.3, 4.4},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.OperatorValue().([]any)) != 4 {
					t.Errorf("expected result to be length 4, got %d", len(result.OperatorValue().([]any)))
				}
				if !slices.Contains(result.OperatorValue().([]any), 1.1) {
					t.Errorf("expected result to contain '1.1', got %v", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), 2.2) {
					t.Errorf("expected result to contain '2.2', got %v", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), 3.3) {
					t.Errorf("expected result to contain '3.3', got %v", result)
				}
				if !slices.Contains(result.OperatorValue().([]any), 4.4) {
					t.Errorf("expected result to contain '4.4', got %v", result)
				}
			},
		},
		"we can MergePolicyOperators two identical map slices": {
			operatorValue1: []map[string]any{
				{
					"foo": "bar",
				},
			},
			operatorValue2: []map[string]any{
				{
					"foo": "bar",
				},
			},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.OperatorValue().([]any)) != 1 {
					t.Errorf("expected result to deduplicate and be length 1, got %d", len(result.OperatorValue().([]any)))
				}

				if diff := cmp.Diff([]any{
					map[string]any{
						"foo": "bar",
					},
				}, result.OperatorValue()); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
		"we can MergePolicyOperators two identical string slices": {
			operatorValue1: []string{"foo-bar", "bar-baz"},
			operatorValue2: []string{"foo-bar", "bar-baz"},
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result.OperatorValue().([]any)) != 2 {
					t.Errorf("expected result to deduplicate and be length 2, got %d", len(result.OperatorValue().([]any)))
				}
				if !reflect.DeepEqual(result.OperatorValue().([]any), []any{"foo-bar", "bar-baz"}) {
					t.Errorf("expected result to match the identical input, got %v", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewAdd(tt.operatorValue1)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.operatorValue2)
			tt.validate(t, result, err)
		})
	}
}
