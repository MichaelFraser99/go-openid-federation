package model

import (
	"testing"
)

// Unit tests for Essential.Resolve:
func TestEssential_Resolve(t *testing.T) {
	tests := map[string]struct {
		metadataParameterValue, operatorValue any
		validate                              func(t *testing.T, result any, err error)
	}{
		"essential is true and metadata is provided": {
			metadataParameterValue: "foo",
			operatorValue:          true,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != "foo" {
					t.Errorf("expected %v, got %v", "foo", result)
				}
			},
		},
		"essential is true and metadata is nil": {
			metadataParameterValue: nil,
			operatorValue:          true,
			validate: func(t *testing.T, result any, err error) {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				if err == nil {
					t.Error("expected error, got none")
				}
				expectedError := "property marked as essential and not provided"
				if err.Error() != expectedError {
					t.Errorf("expected error: %q, got: %q", expectedError, err.Error())
				}
			},
		},
		"essential is false and metadata is nil": {
			metadataParameterValue: nil,
			operatorValue:          false,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
			},
		},
		"essential is false and metadata is provided": {
			metadataParameterValue: "foo",
			operatorValue:          false,
			validate: func(t *testing.T, result any, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result != "foo" {
					t.Errorf("expected %v, got %v", "foo", result)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewEssential(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Resolve(tt.metadataParameterValue)
			tt.validate(t, result, err)
		})
	}
}

// Unit tests for Essential.Merge:
func TestEssential_Merge(t *testing.T) {
	tests := map[string]struct {
		operatorValue, valueToMerge any
		validate                    func(t *testing.T, result MetadataPolicyOperator, err error)
	}{
		"MergePolicyOperators where both values are true": {
			operatorValue: true,
			valueToMerge:  true,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result.OperatorValue() != true {
					t.Errorf("expected %v, got %v", true, result)
				}
			},
		},
		"MergePolicyOperators where one value is true and one is false": {
			operatorValue: true,
			valueToMerge:  false,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result.OperatorValue() != true {
					t.Errorf("expected %v, got %v", true, result)
				}
			},
		},
		"MergePolicyOperators where both values are false": {
			operatorValue: false,
			valueToMerge:  false,
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result.OperatorValue() != false {
					t.Errorf("expected %v, got %v", false, result)
				}
			},
		},
		"MergePolicyOperators fails with non-boolean value": {
			operatorValue: true,
			valueToMerge:  "invalid",
			validate: func(t *testing.T, result MetadataPolicyOperator, err error) {
				if result != nil {
					t.Errorf("expected nil result, got %v", result)
				}
				if err == nil {
					t.Error("expected error, got none")
				}
				expectedError := "MergePolicyOperators value must be a boolean"
				if err.Error() != expectedError {
					t.Errorf("expected error: %q, got: %q", expectedError, err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			operator, err := NewEssential(tt.operatorValue)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := operator.Merge(tt.valueToMerge)
			tt.validate(t, result, err)
		})
	}
}
