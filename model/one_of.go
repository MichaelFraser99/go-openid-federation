package model

import (
	"fmt"
	"reflect"
	"slices"
)

func NewOneOf(operatorValue any) (*OneOf, error) {
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

	return &OneOf{
		operatorValue: anySlice,
	}, nil
}

var (
	_ MetadataPolicyOperator = OneOf{}
)

type OneOf struct {
	operatorValue []any
}

func (o OneOf) OperatorValue() any {
	return o.operatorValue
}

func (o OneOf) ToSlice(key string) MetadataPolicyOperator {
	return o
}

func (o OneOf) String() string {
	return "one_of"
}

// Resolve checks if the metadataParameterValue is present in the operatorValue list.
// If metadataParameterValue is nil, it will simply return nil (indicating no value to check against).
func (o OneOf) Resolve(metadataParameterValue any) (any, error) {
	if o.operatorValue == nil {
		return nil, fmt.Errorf("operator value cannot be nil")
	}

	if metadataParameterValue == nil {
		return nil, nil
	}

	// Ensure the operator value is a slice
	if reflect.TypeOf(o.operatorValue).Kind() != reflect.Slice {
		return nil, fmt.Errorf("operator value must be a slice")
	}

	// Ensure metadata parameter's type matches with items in the operator value
	operatorSlice := reflect.ValueOf(o.operatorValue)
	for i := 0; i < operatorSlice.Len(); i++ {
		if reflect.DeepEqual(metadataParameterValue, operatorSlice.Index(i).Interface()) {
			return metadataParameterValue, nil
		}
	}

	return nil, fmt.Errorf("metadata parameter value %v is not one of the allowed values", metadataParameterValue)
}

// Merge computes the intersection of two operator values.
// If the intersection is empty, an error is returned.
func (o OneOf) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	if valueToMerge == nil {
		return o, nil
	}

	if reflect.TypeOf(o.operatorValue).Kind() != reflect.Slice || reflect.TypeOf(valueToMerge).Kind() != reflect.Slice {
		return nil, fmt.Errorf("both operator values must be slices")
	}

	currentSlice := reflect.ValueOf(o.operatorValue)
	mergeSlice := reflect.ValueOf(valueToMerge)
	intersection := make([]any, 0)

	// Perform intersection
	for i := 0; i < currentSlice.Len(); i++ {
		for j := 0; j < mergeSlice.Len(); j++ {
			if reflect.DeepEqual(currentSlice.Index(i).Interface(), mergeSlice.Index(j).Interface()) {
				intersection = append(intersection, currentSlice.Index(i).Interface())
				break
			}
		}
	}

	if len(intersection) == 0 {
		return nil, fmt.Errorf("intersection of operator values is empty")
	}

	return NewOneOf(intersection)
}

// ResolutionHierarchy defines the order of application for "one_of".
// Operators with lower values in the hierarchy are applied first.
func (o OneOf) ResolutionHierarchy() int {
	return 15
}

func (o OneOf) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if _, ok := p.OperatorValue().([]any); ok {
			return fmt.Errorf("cannot merge policy of type 'one_of' with policy of type 'value' if the value of 'value' is an array")
		}
		if !slices.Contains(o.operatorValue, p.OperatorValue()) {
			return fmt.Errorf("cannot merge policy of type 'one_of' with policy of type 'value' unless the value of 'value' is contained within `one_of`")
		}
	}
	if _, found := containsFunc(reflect.TypeOf(Add{})); found {
		return fmt.Errorf("cannot merge policy of type 'one_of' with policy of type 'add'")
	}
	if _, found := containsFunc(reflect.TypeOf(SubsetOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'one_of' with policy of type 'subset_of'")
	}
	if _, found := containsFunc(reflect.TypeOf(SupersetOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'one_of' with policy of type 'superset_of'")
	}
	return nil
}
