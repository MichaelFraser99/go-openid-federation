package model

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

func scopeOperatorSlice(value any) []any {
	if s, ok := value.(string); ok {
		return ConvertStringsToAnySlice(strings.Split(s, " "))
	}
	return []any{value}
}

func normaliseOperand(value any) (any, bool) {
	switch typed := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return value, true
	case string:
		if !utf8.ValidString(typed) {
			return nil, false
		}
		return value, true
	case float64:
		if typed == 0 {
			return float64(0), true
		}
		return value, true
	case []any:
		if typed == nil {
			return value, true
		}
		normalised := make([]any, len(typed))
		for i, member := range typed {
			replacement, ok := normaliseOperand(member)
			if !ok {
				return nil, false
			}
			normalised[i] = replacement
		}
		return normalised, true
	case map[string]any:
		if typed == nil {
			return value, true
		}
		normalised := make(map[string]any, len(typed))
		for key, member := range typed {
			if !utf8.ValidString(key) {
				return nil, false
			}
			replacement, ok := normaliseOperand(member)
			if !ok {
				return nil, false
			}
			normalised[key] = replacement
		}
		return normalised, true
	}
	return nil, false
}

func canonicalOperandKey(value any) (string, bool) {
	normalised, ok := normaliseOperand(value)
	if !ok {
		return "", false
	}
	raw, err := json.Marshal(normalised)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

const operandWalkLimit = 100

func operandCanMatch(value any) bool {
	return operandValueCanMatch(reflect.ValueOf(value), 0)
}

func operandValueCanMatch(value reflect.Value, depth int) bool {
	if depth > operandWalkLimit {
		return false
	}
	switch value.Kind() {
	case reflect.Float32, reflect.Float64:
		return !math.IsNaN(value.Float())
	case reflect.Complex64, reflect.Complex128:
		held := value.Complex()
		return !math.IsNaN(real(held)) && !math.IsNaN(imag(held))
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return true
		}
		return operandValueCanMatch(value.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			if !operandValueCanMatch(value.Index(i), depth+1) {
				return false
			}
		}
	case reflect.Map:
		for iter := value.MapRange(); iter.Next(); {
			if !operandValueCanMatch(iter.Key(), depth+1) || !operandValueCanMatch(iter.Value(), depth+1) {
				return false
			}
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if !operandValueCanMatch(value.Field(i), depth+1) {
				return false
			}
		}
	case reflect.Func:
		return value.IsNil()
	}
	return true
}

func operandsEqual(left, right any) bool {
	leftKey, leftKeyed := canonicalOperandKey(left)
	rightKey, rightKeyed := canonicalOperandKey(right)
	if leftKeyed && rightKeyed {
		return leftKey == rightKey
	}
	if leftKeyed != rightKeyed {
		return false
	}
	if !operandCanMatch(left) {
		return false
	}
	return reflect.DeepEqual(left, right)
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
		if !operandCanMatch(value) {
			continue
		}
		set.unkeyed = append(set.unkeyed, value)
	}
	return set
}

func (s operandSet) contains(value any) bool {
	if key, ok := canonicalOperandKey(value); ok {
		_, present := s.keyed[key]
		return present
	}
	if !operandCanMatch(value) {
		return false
	}
	return slices.ContainsFunc(s.unkeyed, func(candidate any) bool {
		return reflect.DeepEqual(candidate, value)
	})
}

func (s operandSet) fallbackCount() int {
	return len(s.unkeyed)
}

func newOperandSetFromReflect(values reflect.Value) operandSet {
	collected := make([]any, values.Len())
	for i := range values.Len() {
		collected[i] = values.Index(i).Interface()
	}
	return newOperandSet(collected)
}

func operandsContain(values reflect.Value, value any) bool {
	needle, keyedNeedle := canonicalOperandKey(value)
	if !keyedNeedle && !operandCanMatch(value) {
		return false
	}
	for i := range values.Len() {
		candidate := values.Index(i).Interface()
		if key, ok := canonicalOperandKey(candidate); ok {
			if keyedNeedle && key == needle {
				return true
			}
			continue
		}
		if !keyedNeedle && reflect.DeepEqual(candidate, value) {
			return true
		}
	}
	return false
}

func containsOperand(superset []any, value any) bool {
	return operandsContain(reflect.ValueOf(superset), value)
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

type operandAccumulator struct {
	keyed   map[string]struct{}
	unkeyed []any
}

func newOperandAccumulator(capacity int) *operandAccumulator {
	return &operandAccumulator{keyed: make(map[string]struct{}, capacity)}
}

func (a *operandAccumulator) add(value any) bool {
	if key, ok := canonicalOperandKey(value); ok {
		if _, present := a.keyed[key]; present {
			return false
		}
		a.keyed[key] = struct{}{}
		return true
	}
	if !operandCanMatch(value) {
		return true
	}
	if slices.ContainsFunc(a.unkeyed, func(candidate any) bool {
		return reflect.DeepEqual(candidate, value)
	}) {
		return false
	}
	a.unkeyed = append(a.unkeyed, value)
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
