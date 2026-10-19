package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

func scopeOperatorSlice(value any) []any {
	if s, ok := value.(string); ok {
		return ConvertStringsToAnySlice(strings.Split(s, " "))
	}
	return []any{value}
}

func canonicalOperandKey(value any) (string, bool) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

type operandSet struct {
	keyed   map[string]struct{}
	unkeyed []any
}

func newOperandSet(values []any) operandSet {
	set := operandSet{keyed: make(map[string]struct{}, len(values))}
	for _, value := range values {
		if key, ok := canonicalOperandKey(value); ok {
			set.keyed[key] = struct{}{}
			continue
		}
		set.unkeyed = append(set.unkeyed, value)
	}
	return set
}

func (s operandSet) contains(value any) bool {
	if key, ok := canonicalOperandKey(value); ok {
		if _, present := s.keyed[key]; present {
			return true
		}
	}
	return slices.ContainsFunc(s.unkeyed, func(candidate any) bool {
		return reflect.DeepEqual(candidate, value)
	})
}

func newOperandSetFromReflect(values reflect.Value) operandSet {
	collected := make([]any, values.Len())
	for i := range values.Len() {
		collected[i] = values.Index(i).Interface()
	}
	return newOperandSet(collected)
}

func containsOperand(superset []any, value any) bool {
	return newOperandSet(superset).contains(value)
}

func isSubsetOfOperands(subset, superset []any) bool {
	set := newOperandSet(superset)
	for _, value := range subset {
		if !set.contains(value) {
			return false
		}
	}
	return true
}

type PolicyOperators struct {
	Metadata []MetadataPolicyOperator
}

func (p *PolicyOperators) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '{' {
		var tempMap map[string]any
		err := json.Unmarshal(data, &tempMap)
		if err != nil {
			return fmt.Errorf("unable to parse JSON object as map: %w", err)
		}
		for k, v := range tempMap {
			pMetadata, err := parsePolicyOperator(k, v)
			if err != nil {
				return fmt.Errorf("unable to parse policy operator: %w", err)
			}
			p.Metadata = append(p.Metadata, pMetadata)
		}
	} else {
		return fmt.Errorf("unable to parse %q as a valid Metadata Policy", string(data))
	}
	return nil
}

func parsePolicyOperator(key string, operatorJSON any) (MetadataPolicyOperator, error) {
	var operator MetadataPolicyOperator
	switch key {
	case "add":
		if pOperator, err := NewAdd(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'add' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	case "default":
		if pOperator, err := NewDefault(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'default' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	case "value":
		if pOperator, err := NewValue(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'value' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	case "essential":
		if pOperator, err := NewEssential(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'essential' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	case "one_of":
		if pOperator, err := NewOneOf(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'one_of' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	case "superset_of":
		if pOperator, err := NewSupersetOf(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'superset_of' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	case "subset_of":
		if pOperator, err := NewSubsetOf(operatorJSON); err != nil {
			return nil, fmt.Errorf("unable to parse 'subset_of' policy operator: %w", err)
		} else {
			operator = *pOperator
		}
	default:
		return nil, fmt.Errorf("unknown policy operator: %s", key)
	}
	return operator, nil
}
