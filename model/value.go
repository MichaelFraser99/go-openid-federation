package model

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

var (
	_ MetadataPolicyOperator = Value{}
)

func NewValue(operatorValue any) (*Value, error) {
	return &Value{
		operatorValue: operatorValue,
	}, nil
}

type Value struct {
	operatorValue any
}

func (v Value) OperatorValue() any {
	return v.operatorValue
}

func (v Value) ToSlice(key string) MetadataPolicyOperator {
	if reflect.TypeOf(v.operatorValue).Kind() != reflect.Slice {
		if key == "scope" {
			return &Default{
				operatorValue: strings.Split(v.operatorValue.(string), " "),
			}
		}
		return &Value{
			operatorValue: []any{v.operatorValue},
		}
	}
	return v
}

func (v Value) String() string {
	return "value"
}

// Resolve takes in two values and resolves the 'value' operation.
// Input 'metadataParameterValue' is the value to which the operator is to be applied.
// Input 'operatorValue' is the value the operator will apply to the 'metadataParameterValue' value.
func (v Value) Resolve(metadataParameterValue any) (any, error) {
	inputType := reflect.TypeOf(metadataParameterValue)
	if v.operatorValue == nil { //when input is nil, value should be set to nil. This is not an error case
		return nil, nil
	}
	if metadataParameterValue == nil {
		return v.operatorValue, nil
	}

	if inputType.Kind() != reflect.TypeOf(v.operatorValue).Kind() {
		return nil, fmt.Errorf("type mismatch: metadata parameter value is of type %T, but operator value is of type %T", metadataParameterValue, v.operatorValue)
	}
	return v.operatorValue, nil
}

func (v Value) ResolutionHierarchy() int {
	return 0
}

func (v Value) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	if reflect.DeepEqual(v.operatorValue, valueToMerge) {
		return v, nil
	}
	return nil, fmt.Errorf("merging %v and %v not possible", v.operatorValue, valueToMerge)
}

func (v Value) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Add{})); found {
		sV, ok := v.operatorValue.([]any)
		if !ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'add' if the value of 'value' is not an array")
		}
		for _, v := range p.(Add).operatorValue {
			if !slices.Contains(sV, v) {
				return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'add' unless the contents of `add` is a subset of that in 'value'")
			}
		}
	}
	if _, found := containsFunc(reflect.TypeOf(Default{})); found {
		if _, ok := v.operatorValue.([]any); !ok && v.OperatorValue() == nil { // an empty slice doesn't count as nil
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'default' if the value of 'value' is null")
		}
	}
	if p, found := containsFunc(reflect.TypeOf(OneOf{})); found {
		if _, ok := v.operatorValue.([]any); ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'one_of' if the contents of 'value' is an array")
		} else {
			if !slices.Contains(p.(OneOf).operatorValue, v.OperatorValue()) {
				return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'one_of' unless the value of 'value' is contained within `one_of`")
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(SubsetOf{})); found {
		if sV, ok := v.operatorValue.([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'subset_of' unless the contents of 'value' is an array")
		} else {
			for _, v := range sV {
				if !slices.Contains(p.(SubsetOf).operatorValue, v) {
					return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'subset_of' unless the contents of `value` is a subset of that in 'subset_of'")
				}
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(SupersetOf{})); found {
		if sV, ok := v.operatorValue.([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'superset_of' unless the contents of 'value' is an array")
		} else {
			for _, v := range p.(SupersetOf).operatorValue {
				if !slices.Contains(sV, v) {
					return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'superset_of' unless the contents of `value` is a superset of that in 'superset_of'")
				}
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(Essential{})); found {
		if _, ok := v.operatorValue.([]any); !ok && v.OperatorValue() == nil && p.(Essential).operatorValue { // an empty slice doesn't count as nil
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'essential' if the value of 'value' is null and 'essential' is true")
		}
	}
	return nil
}
