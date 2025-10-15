package model

import (
	"fmt"
	"reflect"
	"strings"
)

func NewDefault(operatorValue any) (*Default, error) {
	if operatorValue == nil {
		return nil, fmt.Errorf("operator value cannot be nil")
	}
	return &Default{
		operatorValue: operatorValue,
	}, nil
}

var (
	_ MetadataPolicyOperator = Default{}
)

type Default struct {
	operatorValue any
}

func (d Default) OperatorValue() any {
	return d.operatorValue
}

func (d Default) ToSlice(key string) MetadataPolicyOperator {
	if reflect.TypeOf(d.operatorValue).Kind() != reflect.Slice {
		if key == "scope" {
			return &Default{
				operatorValue: strings.Split(d.operatorValue.(string), " "),
			}
		}
		return &Default{
			operatorValue: []any{d.operatorValue},
		}
	}
	return d
}

func (d Default) String() string {
	return "default"
}

func (d Default) Resolve(metadataParameterValue any) (any, error) {
	if _, ok := metadataParameterValue.([]any); ok {
		return metadataParameterValue, nil // special case to catch any slice but specifically empty slices which count as a value and should not be processed as nil
	}
	if metadataParameterValue == nil {
		return d.operatorValue, nil
	}
	return metadataParameterValue, nil
}

func (d Default) ResolutionHierarchy() int {
	return 10
}

func (d Default) Merge(valueToMerge any) (MetadataPolicyOperator, error) {
	if reflect.DeepEqual(d.operatorValue, valueToMerge) {
		return d, nil
	} else {
		return nil, fmt.Errorf("merging %v and %v not possible", d.operatorValue, valueToMerge)
	}
}

func (d Default) CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error {
	if p, found := containsFunc(reflect.TypeOf(Value{})); found {
		if _, ok := p.OperatorValue().([]any); !ok && p.OperatorValue() == nil { // an empty slice doesn't count as nil
			return fmt.Errorf("cannot merge policy of type 'default' with policy of type 'value' if the value of 'value' is null")
		}
	}
	return nil
}
