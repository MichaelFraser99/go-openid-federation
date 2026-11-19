package model

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

func scopeTokens(scope string) []string {
	return strings.FieldsFunc(scope, func(r rune) bool { return r == ' ' })
}

func scopeTokenSlice(values []any) []any {
	tokens := make([]any, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok {
			for _, token := range scopeTokens(s) {
				tokens = append(tokens, token)
			}
			continue
		}
		tokens = append(tokens, value)
	}
	return tokens
}

func scopeOperatorSlice(value any) []any {
	if s, ok := value.(string); ok {
		return convertStringsToAnySlice(scopeTokens(s))
	}
	return []any{value}
}

func operandSliceFrom(operatorValue any) ([]any, error) {
	anySlice, err := operandElements(operatorValue)
	if err != nil {
		return nil, err
	}
	if fault := listElementsFault(anySlice); fault != "" {
		return nil, fmt.Errorf("operator value must be an array of one of strings, numbers or objects, and %s", fault)
	}
	return anySlice, nil
}

func operandElements(operatorValue any) ([]any, error) {
	held := reflect.ValueOf(operatorValue)
	if held.Kind() == reflect.Slice && !encodesItself(held.Type()) {
		elements := make([]any, held.Len())
		for i := range held.Len() {
			element, err := storedValue(held.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			elements[i] = element
		}
		return elements, nil
	}
	stored, err := storedValue(operatorValue)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, fmt.Errorf("operator value cannot be nil")
	}
	elements, ok := stored.([]any)
	if !ok {
		return nil, fmt.Errorf("operator value must be a slice")
	}
	return elements, nil
}

func listElementsFault(elements []any) string {
	elementType := ""
	for _, element := range elements {
		named := listOperandElementType(element)
		if named == "" {
			return "holds " + jsonTypeName(element)
		}
		if elementType != "" && named != elementType {
			return fmt.Sprintf("mixes %s and %s", elementType, named)
		}
		elementType = named
	}
	return ""
}

func listOperandElementType(element any) string {
	if element == nil {
		return ""
	}
	if _, ok := element.(json.Number); ok {
		return "numbers"
	}
	switch reflect.TypeOf(element).Kind() {
	case reflect.String:
		return "strings"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "numbers"
	case reflect.Map:
		if reflect.TypeOf(element).Key().Kind() == reflect.String {
			return "objects"
		}
	}
	return ""
}

func jsonTypeName(value any) string {
	if value == nil {
		return "null"
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.Bool:
		return "a boolean"
	case reflect.Slice, reflect.Array:
		return "an array"
	case reflect.Map:
		return "an object with keys that are not strings"
	default:
		return "a value of type " + reflect.TypeOf(value).String()
	}
}

const operandWalkBudget = 100_000

type operandWalk struct {
	remaining       int
	keepsUncopyable bool
}

func newOperandWalk() *operandWalk {
	return &operandWalk{remaining: operandWalkBudget}
}

func (w *operandWalk) step() bool {
	w.remaining--
	return w.remaining >= 0
}

var (
	errPastOperandWalkBudget = errors.New("the value is past the operand walk budget")
	errUnstorableValue       = errors.New("a value cannot be held as JSON")
)

func cloneValue(value any) any {
	walk := newOperandWalk()
	walk.keepsUncopyable = true
	copied, err := walk.copy(value)
	if err != nil {
		return value
	}
	return copied
}

func copyValue(value any) (any, error) {
	return newOperandWalk().copy(value)
}

func (w *operandWalk) copy(value any) (any, error) {
	copied, err := w.clone(value)
	if !errors.Is(err, errPastOperandWalkBudget) {
		return copied, err
	}
	if kind := reflect.TypeOf(value).Kind(); kind == reflect.Map || kind == reflect.Slice {
		return treeViaEncodingJSON(reflect.TypeOf(value), value)
	}
	return treeViaEncodingJSON(reflect.TypeFor[any](), value)
}

func (w *operandWalk) clone(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	if !w.step() {
		return nil, errPastOperandWalkBudget
	}
	original := reflect.ValueOf(value)
	switch original.Kind() {
	case reflect.Map:
		if original.IsNil() {
			return value, nil
		}
		copied := reflect.MakeMapWithSize(original.Type(), original.Len())
		for entries := original.MapRange(); entries.Next(); {
			key, err := w.cloneInto(original.Type().Key(), entries.Key())
			if err != nil {
				return nil, err
			}
			member, err := w.cloneInto(original.Type().Elem(), entries.Value())
			if err != nil {
				return nil, err
			}
			copied.SetMapIndex(key, member)
		}
		return copied.Interface(), nil
	case reflect.Slice:
		if original.IsNil() {
			return value, nil
		}
		copied := reflect.MakeSlice(original.Type(), original.Len(), original.Len())
		for i := range original.Len() {
			member, err := w.cloneInto(original.Type().Elem(), original.Index(i))
			if err != nil {
				return nil, err
			}
			copied.Index(i).Set(member)
		}
		return copied.Interface(), nil
	case reflect.Pointer, reflect.Struct, reflect.Array:
		stored, err := w.storedValue(value)
		if err != nil && w.keepsUncopyable && !errors.Is(err, errPastOperandWalkBudget) {
			return value, nil
		}
		return stored, err
	default:
		return value, nil
	}
}

func (w *operandWalk) cloneInto(elementType reflect.Type, element reflect.Value) (reflect.Value, error) {
	if element.Kind() == reflect.Interface && element.IsNil() {
		return reflect.Zero(elementType), nil
	}
	copied, err := w.clone(element.Interface())
	if err != nil {
		return reflect.Value{}, err
	}
	if copied == nil {
		return reflect.Zero(elementType), nil
	}
	held := reflect.ValueOf(copied)
	if held.Type().AssignableTo(elementType) {
		return held, nil
	}
	decoded, err := decodedJSONAs(elementType, element.Interface())
	if err != nil && w.keepsUncopyable {
		return element, nil
	}
	if err != nil {
		return reflect.Value{}, err
	}
	return reflect.ValueOf(decoded), nil
}

var (
	jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

func encodesItself(valueType reflect.Type) bool {
	for _, candidate := range []reflect.Type{valueType, reflect.PointerTo(valueType)} {
		if candidate.Implements(jsonMarshalerType) || candidate.Implements(textMarshalerType) {
			return true
		}
	}
	return false
}

func storedValue(value any) (any, error) {
	stored, err := newOperandWalk().storedValue(value)
	if errors.Is(err, errPastOperandWalkBudget) {
		return treeViaEncodingJSON(reflect.TypeFor[any](), value)
	}
	return stored, err
}

func (w *operandWalk) storedValue(value any) (any, error) {
	if !w.step() {
		return nil, errPastOperandWalkBudget
	}
	switch typed := value.(type) {
	case nil, bool, string, json.Number, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return value, nil
	case map[string]any:
		if typed == nil {
			return typed, nil
		}
		stored := make(map[string]any, len(typed))
		for key, member := range typed {
			copied, err := w.storedValue(member)
			if err != nil {
				return nil, err
			}
			stored[key] = copied
		}
		return stored, nil
	case []any:
		if typed == nil {
			return typed, nil
		}
		stored := make([]any, len(typed))
		for i, member := range typed {
			copied, err := w.storedValue(member)
			if err != nil {
				return nil, err
			}
			stored[i] = copied
		}
		return stored, nil
	}
	held := reflect.ValueOf(value)
	if !encodesItself(held.Type()) {
		switch held.Kind() {
		case reflect.Slice:
			if held.Type().Elem().Kind() == reflect.Uint8 {
				break
			}
			if held.IsNil() {
				return []any(nil), nil
			}
			return w.storedElements(held)
		case reflect.Map:
			if held.Type().Key().Kind() != reflect.String {
				return w.clone(value)
			}
			if encodesItself(held.Type().Key()) {
				break
			}
			if held.IsNil() {
				return nil, nil
			}
			stored := make(map[string]any, held.Len())
			for entries := held.MapRange(); entries.Next(); {
				member, err := w.storedValue(entries.Value().Interface())
				if err != nil {
					return nil, err
				}
				stored[entries.Key().String()] = member
			}
			return stored, nil
		}
	}
	if !w.fits(held) {
		return nil, errPastOperandWalkBudget
	}
	return decodedJSONAs(reflect.TypeFor[any](), value)
}

func (w *operandWalk) storedElements(held reflect.Value) (any, error) {
	stored := make([]any, held.Len())
	for i := range held.Len() {
		member, err := w.storedValue(held.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		stored[i] = member
	}
	return stored, nil
}

func treeViaEncodingJSON(target reflect.Type, value any) (any, error) {
	if reachesAReferenceTwice(reflect.ValueOf(value), map[heldReference]struct{}{}) {
		return nil, fmt.Errorf("%w: it is past the operand walk budget and reaches the same map, slice or pointer more than once", errUnstorableValue)
	}
	return decodedJSONAs(target, value)
}

func decodedJSONAs(target reflect.Type, value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnstorableValue, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoded := reflect.New(target)
	if err := decoder.Decode(decoded.Interface()); err != nil {
		return nil, fmt.Errorf("%w: %w", errUnstorableValue, err)
	}
	if target.Kind() == reflect.Interface {
		return exactNumbers(decoded.Elem().Interface()), nil
	}
	return decoded.Elem().Interface(), nil
}

func exactNumbers(value any) any {
	switch typed := value.(type) {
	case json.Number:
		return exactNumber(typed)
	case map[string]any:
		for key, member := range typed {
			typed[key] = exactNumbers(member)
		}
	case []any:
		for i, member := range typed {
			typed[i] = exactNumbers(member)
		}
	}
	return value
}

func exactNumber(number json.Number) any {
	if integer, err := strconv.ParseInt(string(number), 10, 64); err == nil {
		return integer
	}
	if integer, err := strconv.ParseUint(string(number), 10, 64); err == nil {
		return integer
	}
	float, _ := strconv.ParseFloat(string(number), 64)
	if encoded, err := json.Marshal(float); err != nil || string(encoded) != string(number) {
		return number
	}
	return float
}

type heldReference struct {
	pointer   uintptr
	length    int
	valueType reflect.Type
}

func reachesAReferenceTwice(value reflect.Value, seen map[heldReference]struct{}) bool {
	if !value.IsValid() {
		return false
	}
	if value.Kind() != reflect.Interface && encodesItself(value.Type()) {
		return false
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return false
		}
		return reachesAReferenceTwice(value.Elem(), seen)
	case reflect.Pointer:
		if value.IsNil() {
			return false
		}
		if value.Type().Elem().Size() > 0 && !firstVisit(seen, heldReference{pointer: value.Pointer(), valueType: value.Type()}) {
			return true
		}
		return reachesAReferenceTwice(value.Elem(), seen)
	case reflect.Map:
		if value.IsNil() {
			return false
		}
		if !firstVisit(seen, heldReference{pointer: value.Pointer(), valueType: value.Type()}) {
			return true
		}
		for entries := value.MapRange(); entries.Next(); {
			if reachesAReferenceTwice(entries.Key(), seen) || reachesAReferenceTwice(entries.Value(), seen) {
				return true
			}
		}
	case reflect.Slice:
		if value.Len() > 0 && value.Type().Elem().Size() > 0 && !firstVisit(seen, heldReference{pointer: value.Pointer(), length: value.Len(), valueType: value.Type()}) {
			return true
		}
		for i := range value.Len() {
			if reachesAReferenceTwice(value.Index(i), seen) {
				return true
			}
		}
	case reflect.Array:
		for i := range value.Len() {
			if reachesAReferenceTwice(value.Index(i), seen) {
				return true
			}
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if (field.IsExported() || field.Anonymous) && reachesAReferenceTwice(value.Field(i), seen) {
				return true
			}
		}
	}
	return false
}

func firstVisit(seen map[heldReference]struct{}, reference heldReference) bool {
	if _, visited := seen[reference]; visited {
		return false
	}
	seen[reference] = struct{}{}
	return true
}

func (w *operandWalk) fits(value reflect.Value) bool {
	if !w.step() {
		return false
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			return w.fits(value.Elem())
		}
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			if !w.fits(value.Index(i)) {
				return false
			}
		}
	case reflect.Map:
		for entries := value.MapRange(); entries.Next(); {
			if !w.fits(entries.Key()) || !w.fits(entries.Value()) {
				return false
			}
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if !w.fits(value.Field(i)) {
				return false
			}
		}
	}
	return true
}

func normaliseOperand(value any) (any, bool) {
	return newOperandWalk().normalise(value)
}

func (w *operandWalk) normalise(value any) (any, bool) {
	if !w.step() {
		return nil, false
	}
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
			replacement, ok := w.normalise(member)
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
			replacement, ok := w.normalise(member)
			if !ok {
				return nil, false
			}
			normalised[key] = replacement
		}
		return normalised, true
	}
	return nil, false
}

var operandWork atomic.Int64

func canonicalOperandKey(value any) (string, bool) {
	operandWork.Add(1)
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

func operandCanMatch(value any) bool {
	return newOperandWalk().canMatch(reflect.ValueOf(value))
}

func (w *operandWalk) canMatch(value reflect.Value) bool {
	if value.Kind() == reflect.Interface && !value.IsNil() {
		return w.canMatch(value.Elem())
	}
	if !w.step() {
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
		return w.canMatch(value.Elem())
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			if !w.canMatch(value.Index(i)) {
				return false
			}
		}
	case reflect.Map:
		for iter := value.MapRange(); iter.Next(); {
			if !w.canMatch(iter.Key()) || !w.canMatch(iter.Value()) {
				return false
			}
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if !w.canMatch(value.Field(i)) {
				return false
			}
		}
	case reflect.Func:
		return value.IsNil()
	}
	return true
}

func operandHash(value any) uint64 {
	hash, ok := newOperandWalk().hash(reflect.ValueOf(value))
	if !ok {
		return 0
	}
	return hash
}

func mixOperandHash(hash, value uint64) uint64 {
	hash ^= value
	hash *= 1099511628211
	return hash
}

func mixOperandHashString(hash uint64, value string) uint64 {
	for i := range len(value) {
		hash = mixOperandHash(hash, uint64(value[i]))
	}
	return mixOperandHash(hash, uint64(len(value)))
}

func operandFloatBits(value float64) uint64 {
	if value == 0 {
		value = 0
	}
	return math.Float64bits(value)
}

func (w *operandWalk) hash(value reflect.Value) (uint64, bool) {
	if value.Kind() == reflect.Interface && !value.IsNil() {
		return w.hash(value.Elem())
	}
	if !w.step() {
		return 0, false
	}
	hash := uint64(14695981039346656037)
	if !value.IsValid() {
		return hash, true
	}
	hash = mixOperandHashString(hash, value.Type().String())
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			hash = mixOperandHash(hash, 1)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		hash = mixOperandHash(hash, uint64(value.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		hash = mixOperandHash(hash, value.Uint())
	case reflect.Float32, reflect.Float64:
		hash = mixOperandHash(hash, operandFloatBits(value.Float()))
	case reflect.Complex64, reflect.Complex128:
		held := value.Complex()
		hash = mixOperandHash(mixOperandHash(hash, operandFloatBits(real(held))), operandFloatBits(imag(held)))
	case reflect.String:
		hash = mixOperandHashString(hash, value.String())
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return hash, true
		}
		inner, ok := w.hash(value.Elem())
		if !ok {
			return 0, false
		}
		hash = mixOperandHash(hash, inner)
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return hash, true
		}
		hash = mixOperandHash(hash, uint64(value.Len()))
		for i := range value.Len() {
			inner, ok := w.hash(value.Index(i))
			if !ok {
				return 0, false
			}
			hash = mixOperandHash(hash, inner)
		}
	case reflect.Map:
		if value.IsNil() {
			return hash, true
		}
		var entries uint64
		for iter := value.MapRange(); iter.Next(); {
			key, ok := w.hash(iter.Key())
			if !ok {
				return 0, false
			}
			member, ok := w.hash(iter.Value())
			if !ok {
				return 0, false
			}
			entries += mixOperandHash(mixOperandHash(14695981039346656037, key), member)
		}
		hash = mixOperandHash(mixOperandHash(hash, uint64(value.Len())), entries)
	case reflect.Struct:
		for i := range value.NumField() {
			inner, ok := w.hash(value.Field(i))
			if !ok {
				return 0, false
			}
			hash = mixOperandHash(hash, inner)
		}
	}
	return hash, true
}

type unkeyedOperands map[uint64][]any

func (u unkeyedOperands) contains(value any, hash uint64) bool {
	return slices.ContainsFunc(u[hash], func(candidate any) bool {
		operandWork.Add(1)
		return reflect.DeepEqual(candidate, value)
	})
}

func (u unkeyedOperands) add(value any, hash uint64) {
	u[hash] = append(u[hash], value)
}

func (u unkeyedOperands) count() int {
	total := 0
	for _, bucket := range u {
		total += len(bucket)
	}
	return total
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
	unkeyed unkeyedOperands
}

func newOperandSet(values []any) operandSet {
	set := operandSet{keyed: make(map[string]struct{}, len(values)), unkeyed: unkeyedOperands{}}
	for _, value := range values {
		if key, ok := canonicalOperandKey(value); ok {
			set.keyed[key] = struct{}{}
			continue
		}
		if !operandCanMatch(value) {
			continue
		}
		set.unkeyed.add(value, operandHash(value))
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
	return s.unkeyed.contains(value, operandHash(value))
}

func (s operandSet) fallbackCount() int {
	return s.unkeyed.count()
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
		operandWork.Add(1)
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
	unkeyed unkeyedOperands
}

func newOperandAccumulator(capacity int) *operandAccumulator {
	return &operandAccumulator{keyed: make(map[string]struct{}, capacity), unkeyed: unkeyedOperands{}}
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
	hash := operandHash(value)
	if a.unkeyed.contains(value, hash) {
		return false
	}
	a.unkeyed.add(value, hash)
	return true
}

type PolicyOperators struct {
	Metadata     []MetadataPolicyOperator
	Unrecognised []string
}

func (p *PolicyOperators) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	if data[0] == '{' {
		var tempMap map[string]any
		err := json.Unmarshal(data, &tempMap)
		if err != nil {
			return fmt.Errorf("unable to parse JSON object as map: %w", err)
		}
		for k, v := range tempMap {
			if !slices.Contains(standardPolicyOperators, k) {
				p.Unrecognised = append(p.Unrecognised, k)
				continue
			}
			pMetadata, err := parsePolicyOperator(k, v)
			if err != nil {
				return fmt.Errorf("unable to parse policy operator: %w", err)
			}
			p.Metadata = append(p.Metadata, pMetadata)
		}
	} else {
		return fmt.Errorf("a metadata policy must be a JSON object, not %s", jsonKind(data))
	}
	slices.Sort(p.Unrecognised)
	return nil
}

func jsonKind(data []byte) string {
	if string(data) == "null" {
		return "null"
	}
	switch data[0] {
	case '[':
		return "an array"
	case '"':
		return "a string"
	case 't', 'f':
		return "a boolean"
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return "a number"
	}
	return "a value that is not valid JSON"
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
