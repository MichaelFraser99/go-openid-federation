package model

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
)

var (
	_ MetadataPolicyOperator = Add{}
)

func NewAdd(operatorValue any) (*Add, error) {
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

	return &Add{
		operatorValue: anySlice,
	}, nil
}

// Add takes in two values and resolves the 'add' operation.
// Input 'metadataParameterValue' is the value to which the operator is to be applied. It must be a valid slice of strings, map[string]any, or any number type
// Input 'operatorValue' is the value the operator will apply to the 'metadataParameterValue' value.
type Add struct {
	operatorValue []any
}

func (a Add) OperatorValue() any {
	return a.operatorValue
}

func (a Add) String() string {
	return "add"
}

func (a Add) Resolve(metadataParameterValue any) (any, error) {
	return a.combineArray(metadataParameterValue)
}

func (a Add) ResolutionHierarchy() int {
	return 5
}

func (a Add) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	val, err := a.combineArray(valueToMerge)
	if err != nil {
		return nil, err
	}
	return NewAdd(val)
}

func (a Add) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		sV, ok := p.OperatorValue().([]any)
		if !ok {
			return fmt.Errorf("cannot merge policy of type 'add' with policy of type 'value' if the value of 'value' is not an array")
		}
		for _, v := range a.operatorValue {
			if !slices.Contains(sV, v) {
				return fmt.Errorf("cannot merge policy of type 'add' with policy of type 'value' unless the contents of `add` is a subset of that in 'value'")
			}
		}
	}
	if _, found := containsFunc(reflect.TypeOf(OneOf{})); found {
		return fmt.Errorf("cannot merge policy of type 'add' with policy of type 'one_of'")
	}
	if p, found := containsFunc(reflect.TypeOf(SubsetOf{})); found {
		sV := p.OperatorValue().([]any)
		for _, v := range a.operatorValue {
			if !slices.Contains(sV, v) {
				return fmt.Errorf("cannot merge policy of type 'add' with policy of type 'subset_of' unless the contents of `add` is a subset of that in 'subset_of'")
			}
		}
	}
	return nil
}

func (a Add) combineArray(metadataParameterValue any) (any, error) {
	if metadataParameterValue == nil {
		return a.operatorValue, nil
	}

	if reflect.TypeOf(metadataParameterValue).Kind() != reflect.Slice || reflect.TypeOf(a.operatorValue).Kind() != reflect.Slice {
		return nil, fmt.Errorf("both inputs must be slices")
	}

	sliceA := reflect.ValueOf(metadataParameterValue)
	sliceB := reflect.ValueOf(a.operatorValue)

	if sliceA.Len() == 0 && sliceB.Len() == 0 {
		return metadataParameterValue, nil // both are empty slices, return an empty slice
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
			// Sort keys to ensure a consistent hash
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

// Helper function to ensure valid element types
func isValidElement(element any) bool {
	switch element.(type) {
	case string, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, map[string]any:
		return true
	default:
		return false
	}
}
