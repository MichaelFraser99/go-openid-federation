package model

import (
	"fmt"
	"reflect"
)

var (
	_ MetadataPolicyOperator = Value{}
)

func NewValue(operatorValue any) (*Value, error) {
	return &Value{
		operatorValue: asJSONOperand(operatorValue),
	}, nil
}

type Value struct {
	operatorValue any
}

func (v Value) OperatorValue() any {
	return cloneValue(v.operatorValue)
}

func (v Value) ToSlice(key string) MetadataPolicyOperator {
	if v.operatorValue == nil {
		return v
	}
	if values, ok := v.operatorValue.([]any); ok {
		if key == "scope" {
			return Value{
				operatorValue: scopeTokenSlice(values),
			}
		}
		return v
	}
	if reflect.TypeOf(v.operatorValue).Kind() != reflect.Slice {
		if key == "scope" {
			return Value{
				operatorValue: scopeOperatorSlice(v.operatorValue),
			}
		}
		return Value{
			operatorValue: []any{v.operatorValue},
		}
	}
	return v
}

func (v Value) String() string {
	return "value"
}

func (v Value) Resolve(any) (any, error) {
	return v.operatorValue, nil
}

func (v Value) ResolutionHierarchy() int {
	return 0
}

func (v Value) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	if operandsEqual(v.operatorValue, valueToMerge) {
		return v, nil
	}
	return nil, fmt.Errorf("two levels of the trust chain set a different 'value', which cannot be merged")
}

func (v Value) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Add{})); found {
		sV, ok := v.operatorValue.([]any)
		if !ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'add' if the value of 'value' is not an array")
		}
		if !isSubsetOfOperands(p.(Add).operatorValue, sV) {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'add' unless the contents of `add` is a subset of that in 'value'")
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
			if !containsOperand(p.(OneOf).operatorValue, v.OperatorValue()) {
				return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'one_of' unless the value of 'value' is contained within `one_of`")
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(SubsetOf{})); found {
		if sV, ok := v.operatorValue.([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'subset_of' unless the contents of 'value' is an array")
		} else {
			if !isSubsetOfOperands(sV, p.(SubsetOf).operatorValue) {
				return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'subset_of' unless the contents of `value` is a subset of that in 'subset_of'")
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(SupersetOf{})); found {
		if sV, ok := v.operatorValue.([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'superset_of' unless the contents of 'value' is an array")
		} else {
			if !isSubsetOfOperands(p.(SupersetOf).operatorValue, sV) {
				return fmt.Errorf("cannot merge policy of type 'value' with policy of type 'superset_of' unless the contents of `value` is a superset of that in 'superset_of'")
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
