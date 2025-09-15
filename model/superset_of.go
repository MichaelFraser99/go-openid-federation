package model

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
)

var (
	_ MetadataPolicyOperator = SupersetOf{}
)

func NewSupersetOf(operatorValue any) (*SupersetOf, error) {
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

	return &SupersetOf{
		operatorValue: anySlice,
	}, nil
}

type SupersetOf struct {
	operatorValue []any
}

func (s SupersetOf) OperatorValue() any {
	return s.operatorValue
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

	// Compute intersection
	for i := 0; i < operatorSlice.Len(); i++ {
		found := false
		for j := 0; j < metadataSlice.Len(); j++ {
			if reflect.DeepEqual(operatorSlice.Index(i).Interface(), metadataSlice.Index(j).Interface()) {
				found = true
				break
			}
		}
		if !found {
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
	return NewSupersetOf(val)
}

func (s SupersetOf) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if sV, ok := p.OperatorValue().([]any); !ok {
			return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'value' unless the value of 'value' is an array")
		} else {
			for _, v := range s.operatorValue {
				if !slices.Contains(sV, v) {
					return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'value' unless the contents of `value` is a superset of that in 'superset_of'")
				}
			}
		}
	}
	if _, found := containsFunc(reflect.TypeOf(OneOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'one_of'")
	}
	if p, found := containsFunc(reflect.TypeOf(SubsetOf{})); found {
		for _, v := range s.operatorValue {
			if !slices.Contains(p.OperatorValue().([]any), v) {
				return fmt.Errorf("cannot merge policy of type 'superset_of' with policy of type 'subset_of' unless the contents of `subset_of` is a superset of that in 'superset_of'")
			}
		}
	}
	return nil
}

func (s SupersetOf) combineArray(metadataParameterValue any) (any, error) {
	if metadataParameterValue == nil {
		return s, nil
	}

	if reflect.TypeOf(metadataParameterValue).Kind() != reflect.Slice {
		return nil, fmt.Errorf("input must be a slice")
	}

	sliceA := reflect.ValueOf(metadataParameterValue)
	sliceB := reflect.ValueOf(s.operatorValue)

	if sliceA.Len() == 0 && sliceB.Len() == 0 {
		return s, nil
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
	seen := make(map[string]bool)

	hashElement := func(element any) (string, error) {
		switch e := element.(type) {
		case map[string]any:
			keys := make([]string, 0, len(e))
			for k := range e {
				keys = append(keys, k)
			}
			// Sort keys to ensure consistent hash
			sort.Strings(keys)
			sortedMap := make([]string, 0, len(e)*2)
			for _, k := range keys {
				sortedMap = append(sortedMap, k, fmt.Sprintf("%v", e[k]))
			}
			return fmt.Sprintf("%v", sortedMap), nil
		default:
			return fmt.Sprintf("%#v", element), nil
		}
	}

	for i := 0; i < sliceA.Len(); i++ {
		elem := sliceA.Index(i).Interface()
		if isValidElement(elem) {
			hash, err := hashElement(elem)
			if err != nil {
				return nil, fmt.Errorf("failed to hash element in sliceA: %v", err)
			}
			if !seen[hash] {
				seen[hash] = true
				result = reflect.Append(result, reflect.ValueOf(elem))
			}
		} else {
			return nil, fmt.Errorf("invalid element type in sliceA: %v", elem)
		}
	}

	for i := 0; i < sliceB.Len(); i++ {
		elem := sliceB.Index(i).Interface()
		if isValidElement(elem) {
			hash, err := hashElement(elem)
			if err != nil {
				return nil, fmt.Errorf("failed to hash element in sliceB: %v", err)
			}
			if !seen[hash] {
				seen[hash] = true
				result = reflect.Append(result, reflect.ValueOf(elem))
			}
		} else {
			return nil, fmt.Errorf("invalid element type in sliceB: %v", elem)
		}
	}

	return result.Interface(), nil
}
