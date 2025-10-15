package model

import (
	"fmt"
	"reflect"
)

var (
	_ MetadataPolicyOperator = Essential{}
)

func NewEssential(operatorValue any) (*Essential, error) {
	if _, ok := operatorValue.([]any); ok {
		return nil, fmt.Errorf("operator value must be a boolean")
	}
	if operatorValue == nil {
		return &Essential{
			operatorValue: false,
		}, nil
	}
	if bOperatorValue, ok := operatorValue.(bool); !ok {
		return nil, fmt.Errorf("operator value must be a boolean")
	} else {
		return &Essential{
			operatorValue: bOperatorValue,
		}, nil
	}
}

type Essential struct {
	operatorValue bool
}

func (s Essential) OperatorValue() any {
	return s.operatorValue
}

func (s Essential) ToSlice(key string) MetadataPolicyOperator {
	return s
}

func (s Essential) String() string {
	return "essential"
}

func (s Essential) Resolve(metadataParameterValue any) (any, error) {
	if _, ok := metadataParameterValue.([]any); ok {
		return metadataParameterValue, nil // special case to catch any slice but specifically empty slices which count as a value and are valid if essential is true
	}
	if s.operatorValue && metadataParameterValue == nil {
		return nil, fmt.Errorf("property marked as essential and not provided")
	} else {
		return metadataParameterValue, nil
	}
}

func (s Essential) ResolutionHierarchy() int {
	return 100 // last
}

func (s Essential) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	if reflect.TypeOf(valueToMerge).Kind() != reflect.Bool {
		return nil, fmt.Errorf("MergePolicyOperators value must be a boolean")
	}

	return NewEssential(s.operatorValue || valueToMerge.(bool))
}

func (s Essential) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if _, ok := p.OperatorValue().([]any); !ok && p.OperatorValue() == nil && s.operatorValue { // an empty slice doesn't count as nil
			return fmt.Errorf("cannot merge policy of type 'essential' with policy of type 'value' if the value of 'value' is null and 'essential' is true")
		}
	}
	return nil
}
