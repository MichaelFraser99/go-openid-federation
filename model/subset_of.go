package model

import (
	"fmt"
	"reflect"
)

var (
	_ MetadataPolicyOperator = SubsetOf{}
)

func NewSubsetOf(operatorValue any) (*SubsetOf, error) {
	anySlice, err := operandSliceFrom(operatorValue)
	if err != nil {
		return nil, err
	}

	return &SubsetOf{
		operatorValue: DeduplicateSlice(anySlice),
	}, nil
}

type SubsetOf struct {
	operatorValue []any
}

func (s SubsetOf) OperatorValue() any {
	return s.operatorValue
}

func (s SubsetOf) ToSlice(key string) MetadataPolicyOperator {
	return s
}

func (s SubsetOf) String() string {
	return "subset_of"
}

func (s SubsetOf) Resolve(metadataParameterValue any) (any, error) {
	// If metadata is nil, return nil (as the parameter is "removed")
	if metadataParameterValue == nil {
		return nil, nil
	}

	// Both operator and metadata values must be slices
	if reflect.TypeOf(s.operatorValue).Kind() != reflect.Slice || reflect.TypeOf(metadataParameterValue).Kind() != reflect.Slice {
		return nil, fmt.Errorf("both metadata and operator values must be slices")
	}

	operatorSlice := reflect.ValueOf(s.operatorValue)
	metadataSlice := reflect.ValueOf(metadataParameterValue)

	var intersection []any

	// Compute intersection
	allowed := newOperandSetFromReflect(operatorSlice)
	for i := range metadataSlice.Len() {
		value := metadataSlice.Index(i).Interface()
		if allowed.contains(value) {
			intersection = append(intersection, value)
		}
	}

	return intersection, nil
}

func (s SubsetOf) ResolutionHierarchy() int {
	return 20 // After one_of
}

func (s SubsetOf) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	// Both operator values must be slices
	if reflect.TypeOf(s.operatorValue).Kind() != reflect.Slice || reflect.TypeOf(valueToMerge).Kind() != reflect.Slice {
		return nil, fmt.Errorf("both operator values must be slices")
	}

	operatorSlice := reflect.ValueOf(s.operatorValue)
	mergeSlice := reflect.ValueOf(valueToMerge)
	intersection := []any{}

	// Compute intersection
	incoming := newOperandSetFromReflect(mergeSlice)
	for i := range operatorSlice.Len() {
		value := operatorSlice.Index(i).Interface()
		if incoming.contains(value) {
			intersection = append(intersection, value)
		}
	}

	merged, err := NewSubsetOf(intersection)
	if err != nil {
		return nil, err
	}
	return *merged, nil
}

func (s SubsetOf) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if sV, ok := p.OperatorValue().([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'value' unless the value of 'value' is an array")
		} else {
			if !isSubsetOfOperands(sV, s.operatorValue) {
				return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'value' unless the contents of `value` is a subset of that in 'subset_of'")
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(Add{})); found {
		sV := p.OperatorValue().([]any)
		if !isSubsetOfOperands(sV, s.operatorValue) {
			return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'add' unless the contents of `add` is a subset of that in 'subset_of'")
		}
	}
	if _, found := containsFunc(reflect.TypeOf(OneOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'one_of'")
	}
	if p, found := containsFunc(reflect.TypeOf(SupersetOf{})); found {
		sV := p.OperatorValue().([]any)
		if !isSubsetOfOperands(sV, s.operatorValue) {
			return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'superset_of' unless the contents of 'subset_of' is a superset of that in 'superset_of'")
		}
	}
	return nil
}
