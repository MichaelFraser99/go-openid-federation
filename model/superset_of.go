package model

import (
	"fmt"
	"reflect"
)

var (
	_ MetadataPolicyOperator = SupersetOf{}
)

func NewSupersetOf(operatorValue any) (*SupersetOf, error) {
	anySlice, err := operandSliceFrom(operatorValue)
	if err != nil {
		return nil, err
	}

	return &SupersetOf{
		operatorValue: DeduplicateSlice(anySlice),
	}, nil
}

type SupersetOf struct {
	operatorValue []any
}

func (s SupersetOf) OperatorValue() any {
	return s.operatorValue
}

func (s SupersetOf) ToSlice(key string) MetadataPolicyOperator {
	return s
}

func (s SupersetOf) String() string {
	return "superset_of"
}

func (s SupersetOf) Resolve(metadataParameterValue any) (any, error) {
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

	if operatorSlice.Len() == 0 {
		return metadataParameterValue, nil
	}

	// Compute intersection
	present := newOperandSetFromReflect(metadataSlice)
	for i := range operatorSlice.Len() {
		if !present.contains(operatorSlice.Index(i).Interface()) {
			return nil, fmt.Errorf("provided metadata is not a superset of the defined operator values")
		}
	}

	return metadataParameterValue, nil
}

func (s SupersetOf) ResolutionHierarchy() int {
	return 25 // After subset_of
}

func (s SupersetOf) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	val, err := s.combineArray(valueToMerge)
	if err != nil {
		return nil, err
	}

	anySlice, err := operandSliceFrom(val)
	if err != nil {
		return nil, err
	}

	return &SupersetOf{operatorValue: anySlice}, nil
}

func (s SupersetOf) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if sV, ok := p.OperatorValue().([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'value' unless the value of 'value' is an array")
		} else {
			if !isSubsetOfOperands(s.operatorValue, sV) {
				return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'value' unless the contents of `value` is a superset of that in 'superset_of'")
			}
		}
	}
	if _, found := containsFunc(reflect.TypeOf(OneOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'one_of'")
	}
	if p, found := containsFunc(reflect.TypeOf(SubsetOf{})); found {
		if !isSubsetOfOperands(s.operatorValue, p.OperatorValue().([]any)) {
			return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'subset_of' unless the contents of `subset_of` is a superset of that in 'superset_of'")
		}
	}
	return nil
}

func (s SupersetOf) combineArray(metadataParameterValue any) (any, error) {
	if metadataParameterValue == nil {
		return s.operatorValue, nil
	}

	if reflect.TypeOf(metadataParameterValue).Kind() != reflect.Slice {
		return nil, fmt.Errorf("input must be a slice")
	}

	sliceA := reflect.ValueOf(metadataParameterValue)
	sliceB := reflect.ValueOf(s.operatorValue)

	if sliceA.Len() == 0 && sliceB.Len() == 0 {
		return s.operatorValue, nil
	}

	// Assert that the elements of both slices are of the same underlying type
	if sliceA.Len() > 0 && sliceB.Len() > 0 {
		sliceAElementType := reflect.TypeOf(sliceA.Index(0).Interface())
		sliceBElementType := reflect.TypeOf(sliceB.Index(0).Interface())

		if sliceAElementType != sliceBElementType {
			return nil, fmt.Errorf("elements of both slices must be of the same underlying type")
		}
	}

	result := reflect.MakeSlice(sliceA.Type(), 0, sliceA.Len()+sliceB.Len())
	seen := newOperandAccumulator(sliceA.Len() + sliceB.Len())

	for i := 0; i < sliceA.Len(); i++ {
		elem := sliceA.Index(i).Interface()
		if isValidElement(elem) {
			if seen.add(elem) {
				result = reflect.Append(result, reflect.ValueOf(elem))
			}
		} else {
			return nil, fmt.Errorf("invalid element type in sliceA: %v", elem)
		}
	}

	for i := 0; i < sliceB.Len(); i++ {
		elem := sliceB.Index(i).Interface()
		if isValidElement(elem) {
			if seen.add(elem) {
				result = reflect.Append(result, reflect.ValueOf(elem))
			}
		} else {
			return nil, fmt.Errorf("invalid element type in sliceB: %v", elem)
		}
	}

	return result.Interface(), nil
}
