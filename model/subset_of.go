package model

import (
	"fmt"
	"reflect"
	"slices"
)

var (
	_ MetadataPolicyOperator = SubsetOf{}
)

func NewSubsetOf(operatorValue any) (*SubsetOf, error) {
	if operatorValue == nil {
		return nil, fmt.Errorf("operator value cannot be nil")
	}

	if reflect.TypeOf(operatorValue).Kind() != reflect.Slice {
		return nil, fmt.Errorf("operator value must be a slice")
	}

	sliceValue := reflect.ValueOf(operatorValue)
	anySlice := make([]any, sliceValue.Len())

	for i := 0; i < sliceValue.Len(); i++ {
		anySlice[i] = sliceValue.Index(i).Interface()
	}

	return &SubsetOf{
		operatorValue: anySlice,
	}, nil
}

type SubsetOf struct {
	operatorValue []any
}

func (s SubsetOf) OperatorValue() any {
	return s.operatorValue
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
	for i := 0; i < metadataSlice.Len(); i++ {
		for j := 0; j < operatorSlice.Len(); j++ {
			if reflect.DeepEqual(metadataSlice.Index(i).Interface(), operatorSlice.Index(j).Interface()) {
				intersection = append(intersection, metadataSlice.Index(i).Interface())
				break
			}
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
	for i := 0; i < operatorSlice.Len(); i++ {
		for j := 0; j < mergeSlice.Len(); j++ {
			if reflect.DeepEqual(operatorSlice.Index(i).Interface(), mergeSlice.Index(j).Interface()) {
				intersection = append(intersection, operatorSlice.Index(i).Interface())
				break
			}
		}
	}

	if len(intersection) == 0 { // in the event of no intersection, an empty array is returned
		return NewSubsetOf(intersection)
	}

	return NewSubsetOf(intersection)
}

func (s SubsetOf) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if sV, ok := p.OperatorValue().([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'value' unless the value of 'value' is an array")
		} else {
			for _, v := range sV {
				if !slices.Contains(s.operatorValue, v) {
					return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'value' unless the contents of `value` is a subset of that in 'subset_of'")
				}
			}
		}
	}
	if p, found := containsFunc(reflect.TypeOf(Add{})); found {
		sV := p.OperatorValue().([]any)
		for _, v := range sV {
			if !slices.Contains(s.operatorValue, v) {
				return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'add' unless the contents of `add` is a subset of that in 'subset_of'")
			}
		}
	}
	if _, found := containsFunc(reflect.TypeOf(OneOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'one_of'")
	}
	if p, found := containsFunc(reflect.TypeOf(SupersetOf{})); found {
		sV := p.OperatorValue().([]any)
		for _, v := range sV {
			if !slices.Contains(s.operatorValue, v) {
				return fmt.Errorf("cannot merge policy of type 'subset_of' with policy of type 'superset_of' unless the contents of `superset_of` is a superset of that in 'subset_of'")
			}
		}
	}
	return nil
}
