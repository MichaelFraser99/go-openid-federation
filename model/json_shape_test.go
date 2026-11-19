package model

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

type typedContact struct {
	Name  string   `json:"name"`
	Email []string `json:"email"`
}

type shoutedName string

func (s shoutedName) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.ToUpper(string(s)))
}

type goTypedValue struct {
	name   string
	build  func() (value any, write func())
	shaped any
}

func goTypedValues() []goTypedValue {
	return []goTypedValue{
		{
			name: "a josemodel.Jwks",
			build: func() (any, func()) {
				jwks := josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "kid": "original"}}}
				return jwks, func() { jwks.Keys[0]["kid"] = "written" }
			},
			shaped: map[string]any{"keys": []any{map[string]any{"kty": "EC", "kid": "original"}}},
		},
		{
			name: "a pointer to a []string",
			build: func() (any, func()) {
				contacts := []string{"ops@example.com"}
				return &contacts, func() { contacts[0] = "written@example.com" }
			},
			shaped: []any{"ops@example.com"},
		},
		{
			name: "a []map[string]any",
			build: func() (any, func()) {
				keys := []map[string]any{{"kty": "EC", "kid": "original"}}
				return keys, func() { keys[0]["kid"] = "written" }
			},
			shaped: []any{map[string]any{"kty": "EC", "kid": "original"}},
		},
		{
			name: "a struct holding a slice",
			build: func() (any, func()) {
				contact := typedContact{Name: "ops", Email: []string{"ops@example.com"}}
				return contact, func() { contact.Email[0] = "written@example.com" }
			},
			shaped: map[string]any{"name": "ops", "email": []any{"ops@example.com"}},
		},
		{
			name: "a pointer to a struct inside an array",
			build: func() (any, func()) {
				contact := &typedContact{Name: "ops", Email: []string{"ops@example.com"}}
				return []any{contact}, func() { contact.Name = "written" }
			},
			shaped: []any{map[string]any{"name": "ops", "email": []any{"ops@example.com"}}},
		},
		{
			name: "a value that writes its own JSON",
			build: func() (any, func()) {
				names := []any{shoutedName("ops")}
				return names, func() { names[0] = shoutedName("written") }
			},
			shaped: []any{"OPS"},
		},
		{
			name: "a typed map of structs",
			build: func() (any, func()) {
				pairs := map[string]pair{"a": {X: 1}}
				return pairs, func() { pairs["a"] = pair{X: 2} }
			},
			shaped: map[string]any{"a": map[string]any{"x": int64(1)}},
		},
		{
			name: "a named integer a float64 cannot hold exactly",
			build: func() (any, func()) {
				return serial(1<<53 + 1), func() {}
			},
			shaped: int64(1<<53 + 1),
		},
		{
			name: "a struct holding the largest uint64",
			build: func() (any, func()) {
				return counter{Total: math.MaxUint64}, func() {}
			},
			shaped: map[string]any{"total": uint64(math.MaxUint64)},
		},
		{
			name: "a []byte, which encoding/json writes as base64",
			build: func() (any, func()) {
				raw := []byte{0xfb, 0xff, 0x01}
				return raw, func() { raw[0] = 0 }
			},
			shaped: "+/8B",
		},
		{
			name: "a slice type that writes its own JSON",
			build: func() (any, func()) {
				names := shoutedNames{"ops"}
				return names, func() { names[0] = "written" }
			},
			shaped: "OPS",
		},
		{
			name: "a map keyed by a string type that writes its own text",
			build: func() (any, func()) {
				keyed := map[shoutedKey]string{"ops": "a"}
				return keyed, func() { keyed["ops"] = "written" }
			},
			shaped: asEncodingJSONWritesIt(map[shoutedKey]string{"ops": "a"}),
		},
		{
			name: "an array of integers a float64 cannot hold exactly",
			build: func() (any, func()) {
				return counters{Totals: []uint64{math.MaxUint64}}, func() {}
			},
			shaped: map[string]any{"totals": []any{uint64(math.MaxUint64)}},
		},
	}
}

type shoutedNames []string

func (s shoutedNames) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.ToUpper(strings.Join(s, " ")))
}

type shoutedKey string

func (s shoutedKey) MarshalText() ([]byte, error) {
	return []byte(strings.ToUpper(string(s))), nil
}

func asEncodingJSONWritesIt(value any) any {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		panic(err)
	}
	return decoded
}

type counters struct {
	Totals []uint64 `json:"totals"`
}

type pair struct {
	X int `json:"x"`
}

type serial int64

type counter struct {
	Total uint64 `json:"total"`
}

func TestSubordinateStore_HoldsAGoTypedMetadataValueAsItsJSON(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	stores := []struct {
		name  string
		store func(*SubordinateConfiguration) ServerConfiguration
	}{
		{name: "AddSubordinate", store: func(subordinate *SubordinateConfiguration) ServerConfiguration {
			intermediate := &IntermediateConfiguration{}
			intermediate.AddSubordinate(identifier, subordinate)
			return ServerConfiguration{IntermediateConfiguration: intermediate}
		}},
		{name: "the Retriever cache", store: func(subordinate *SubordinateConfiguration) ServerConfiguration {
			cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{SubordinateCacheTime: time.Hour}, MetadataRetriever: &cacheRetriever{subordinate: subordinate}}
			if _, err := cfg.GetSubordinate(context.Background(), identifier); err != nil {
				panic(err)
			}
			return cfg
		}},
	}

	for _, store := range stores {
		for _, tc := range goTypedValues() {
			t.Run(store.name+": "+tc.name, func(t *testing.T) {
				value, write := tc.build()
				cfg := store.store(&SubordinateConfiguration{Metadata: &Metadata{
					OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": value},
					Extensions:                 map[string]map[string]any{"x_type": {"x_param": value}},
				}})

				write()

				stored, err := cfg.GetSubordinate(context.Background(), identifier)
				if err != nil {
					t.Fatalf("expected the subordinate, got %v", err)
				}
				for where, got := range map[string]any{
					"a built-in entity type": (*stored.Metadata.OpenIDRelyingPartyMetadata)["x_param"],
					"an extension":           stored.Metadata.Extensions["x_type"]["x_param"],
				} {
					if !reflect.DeepEqual(got, tc.shaped) {
						t.Errorf("expected %s to be held as its JSON %#v, unchanged by a later write to what was registered, got %#v", where, tc.shaped, got)
					}
				}
			})
		}
	}
}

func TestSubordinateStore_HoldsAGoTypedPolicyOperandAsItsJSON(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	for _, tc := range goTypedValues() {
		t.Run(tc.name, func(t *testing.T) {
			value, write := tc.build()
			pinned, err := NewValue(value)
			if err != nil {
				t.Fatalf("expected the value operator to build, got %v", err)
			}
			intermediate := &IntermediateConfiguration{}
			intermediate.AddSubordinate(identifier, &SubordinateConfiguration{Policies: MetadataPolicy{
				OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"x_param": {Metadata: []MetadataPolicyOperator{*pinned}}},
			}})
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

			write()

			stored, err := cfg.GetSubordinate(context.Background(), identifier)
			if err != nil {
				t.Fatalf("expected the subordinate, got %v", err)
			}
			if got := stored.Policies.OpenIDRelyingPartyMetadata["x_param"].Metadata[0].OperatorValue(); !reflect.DeepEqual(got, tc.shaped) {
				t.Errorf("expected the operand to be held as its JSON %#v, unchanged by a later write to what was registered, got %#v", tc.shaped, got)
			}
		})
	}
}

func TestPolicyOperators_HoldAGoTypedOperandAsItsJSON(t *testing.T) {
	jwks := josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "kid": "original"}}}
	contacts := []string{"ops@example.com"}
	keys := []map[string]any{{"kty": "EC", "kid": "original"}}
	wantKeys := []any{map[string]any{"kty": "EC", "kid": "original"}}

	tests := []struct {
		name  string
		build func() (MetadataPolicyOperator, error)
		want  any
	}{
		{name: "value", build: func() (MetadataPolicyOperator, error) { o, err := NewValue(jwks); return deref(o), err }, want: map[string]any{"keys": wantKeys}},
		{name: "default", build: func() (MetadataPolicyOperator, error) { o, err := NewDefault(jwks); return deref(o), err }, want: map[string]any{"keys": wantKeys}},
		{name: "add", build: func() (MetadataPolicyOperator, error) { o, err := NewAdd(keys); return deref(o), err }, want: wantKeys},
		{name: "one_of", build: func() (MetadataPolicyOperator, error) { o, err := NewOneOf(&contacts); return deref(o), err }, want: []any{"ops@example.com"}},
		{name: "subset_of", build: func() (MetadataPolicyOperator, error) { o, err := NewSubsetOf(&contacts); return deref(o), err }, want: []any{"ops@example.com"}},
		{name: "superset_of", build: func() (MetadataPolicyOperator, error) { o, err := NewSupersetOf(keys); return deref(o), err }, want: wantKeys},
		{name: "value, an object holding a Go-typed array", build: func() (MetadataPolicyOperator, error) {
			o, err := NewValue(map[string]any{"keys": keys})
			return deref(o), err
		}, want: map[string]any{"keys": wantKeys}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			operator, err := tc.build()
			if err != nil {
				t.Fatalf("expected the operator to build, got %v", err)
			}
			jwks.Keys[0]["kid"] = "written"
			keys[0]["kid"] = "written"
			contacts[0] = "written@example.com"
			defer func() {
				jwks.Keys[0]["kid"] = "original"
				keys[0]["kid"] = "original"
				contacts[0] = "ops@example.com"
			}()

			if got := operator.OperatorValue(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected the operand to be held as its JSON %#v, unchanged by a later write to what was given, got %#v", tc.want, got)
			}
			resolved, err := operator.Resolve(nil)
			if err != nil {
				return
			}
			if resolved != nil && !reflect.DeepEqual(resolved, tc.want) {
				t.Errorf("expected Resolve to hand out the JSON %#v, got %#v", tc.want, resolved)
			}
		})
	}
}

func deref[T any](operator *T) MetadataPolicyOperator {
	if operator == nil {
		return nil
	}
	held, _ := any(*operator).(MetadataPolicyOperator)
	return held
}

func TestCloneValue_SharesNothingWithAStructOrPointer(t *testing.T) {
	for _, tc := range goTypedValues() {
		t.Run(tc.name, func(t *testing.T) {
			value, write := tc.build()
			copied := cloneValue(value)

			write()

			got, err := json.Marshal(copied)
			if err != nil {
				t.Fatalf("expected the copy to marshal, got %v", err)
			}
			want, err := json.Marshal(tc.shaped)
			if err != nil {
				t.Fatalf("expected the fixture to marshal, got %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("a write to the original reached the copy: want %s, got %s", want, got)
			}
		})
	}
}

func TestCloneValue_CopiesAGoTypedElementOfATypedContainer(t *testing.T) {
	contact := &typedContact{Name: "ops", Email: []string{"ops@example.com"}}
	original := map[string]*typedContact{"ops": contact}

	copied, ok := cloneValue(original).(map[string]*typedContact)
	if !ok {
		t.Fatalf("expected a typed map to stay a typed map, got %T", cloneValue(original))
	}
	contact.Email[0] = "written@example.com"

	if copied["ops"] == nil || copied["ops"].Email[0] != "ops@example.com" {
		t.Errorf("a write to the original element reached the copy: %+v", copied["ops"])
	}
}

func TestStoredValue_KeepsWhatIsAlreadyJSON(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "null", value: nil},
		{name: "a string", value: "s"},
		{name: "a float64", value: 1.5},
		{name: "an int", value: 3},
		{name: "a bool", value: true},
		{name: "a json.Number", value: json.Number("12")},
		{name: "an object", value: map[string]any{"a": []any{1, "b", map[string]any{"c": nil}}}},
		{name: "an array", value: []any{"a", 2.0, false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := storedValue(tc.value)
			if err != nil {
				t.Fatalf("expected %#v to be stored, got %v", tc.value, err)
			}
			if !reflect.DeepEqual(got, tc.value) {
				t.Errorf("expected %#v to be kept as it is, got %#v", tc.value, got)
			}
		})
	}
}

func TestStoredValue_RefusesAValueThatReachesItselfPastTheWalkBudget(t *testing.T) {
	type node struct {
		Next *node `json:"next"`
	}
	cyclic := &node{}
	cyclic.Next = cyclic
	nested := map[string]any{}
	nested["self"] = nested

	type pair struct {
		Left, Right *pair
	}
	shared := &pair{}
	for range 64 {
		shared = &pair{Left: shared, Right: shared}
	}
	sharedMap := map[string]any{}
	for range 64 {
		sharedMap = map[string]any{"left": sharedMap, "right": sharedMap}
	}
	sharedSlice := []any{"leaf"}
	for range 64 {
		sharedSlice = []any{sharedSlice, sharedSlice}
	}
	sharedEmbedded := &embeddedPair{}
	for range 64 {
		sharedEmbedded = &embeddedPair{embeddedLinks{Left: sharedEmbedded, Right: sharedEmbedded}}
	}
	sharedArray := &arrayPair{}
	for range 64 {
		sharedArray = &arrayPair{Both: [2]*arrayPair{sharedArray, sharedArray}}
	}

	done := make(chan []error)
	go func() {
		var errs []error
		for _, value := range []any{cyclic, nested, shared, sharedMap, sharedSlice, sharedArray, sharedEmbedded} {
			_, err := storedValue(value)
			errs = append(errs, err)
		}
		_ = cloneValue(cyclic)
		_ = cloneValue(shared)
		if copied := cloneValue(nested); copied.(map[string]any) != nil {
			errs = append(errs, errors.New("cloneValue handed out a map that holds itself"))
		}
		done <- errs
	}()
	select {
	case errs := <-done:
		for i, err := range errs {
			if !errors.Is(err, errUnstorableValue) {
				t.Errorf("expected value %d, which no copy can hold, to be refused, got %v", i, err)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("storing a value that refers to itself did not finish")
	}
}

func TestStoredValue_WritesANilPointerAsNull(t *testing.T) {
	var contacts *[]string
	if got, err := storedValue(contacts); err != nil || got != nil {
		t.Errorf("expected a nil pointer to be held as JSON null, got %#v, %v", got, err)
	}
	if got, err := storedValue([]any{contacts}); err != nil || !reflect.DeepEqual(got, []any{nil}) {
		t.Errorf("expected a nil pointer in an array to be held as JSON null, got %#v, %v", got, err)
	}
	if _, err := NewDefault(contacts); err == nil {
		t.Errorf("expected default to refuse an operand whose JSON is null, as it refuses null itself")
	}
}

type emptyMarker struct{}

type privateLinks struct {
	Name  string `json:"name"`
	left  *typedContact
	right *typedContact
}

type embeddedLinks struct {
	Left, Right *embeddedPair
}

type embeddedPair struct {
	embeddedLinks
}

type arrayPair struct {
	Both [2]*arrayPair
}

type sharedInside struct {
	Left, Right *typedContact
}

func (s sharedInside) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Left.Name)
}

type preciseDecimal struct{}

func (preciseDecimal) MarshalJSON() ([]byte, error) {
	return []byte("0.10000000000000000001"), nil
}

type measured struct {
	Ratio float64 `json:"ratio"`
}

func TestStoredValue_StoresAValuePastTheWalkBudgetThatReachesNothingTwice(t *testing.T) {
	contact := &typedContact{Name: "ops"}
	window := []any{"a", "b"}
	extras := []any{
		[]any{}, []any{},
		&emptyMarker{}, &emptyMarker{},
		[]emptyMarker{{}}, []emptyMarker{{}},
		window[:1], window[:2],
		privateLinks{Name: "links", left: contact, right: contact},
		sharedInside{Left: contact, Right: contact},
	}
	values := make([]any, 0, operandWalkBudget+len(extras))
	for i := range operandWalkBudget {
		values = append(values, map[string]any{"v": i})
	}
	values = append(values, extras...)

	stored, err := storedValue(values)
	if err != nil {
		t.Fatalf("expected a value that reaches no map, slice or pointer twice to be stored, got %v", err)
	}
	tail := stored.([]any)[operandWalkBudget:]
	want := []any{[]any{}, []any{}, map[string]any{}, map[string]any{}, []any{map[string]any{}}, []any{map[string]any{}}, []any{"a"}, []any{"a", "b"}, map[string]any{"name": "links"}, "ops"}
	if !reflect.DeepEqual(tail, want) {
		t.Errorf("expected the tail as encoding/json writes it, %#v, got %#v", want, tail)
	}
}

func TestStoredValue_KeepsANumberAFloat64CannotHoldAsWritten(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  any
	}{
		{name: "a decimal a float64 rounds", value: preciseDecimal{}, want: json.Number("0.10000000000000000001")},
		{name: "a float a float64 holds", value: measured{Ratio: 1.5}, want: map[string]any{"ratio": 1.5}},
		{name: "a negative integer", value: serial(-(1<<53 + 1)), want: int64(-(1<<53 + 1))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := storedValue(tc.value)
			if err != nil {
				t.Fatalf("expected the value to be stored, got %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected %#v, got %#v", tc.want, got)
			}
		})
	}
}

func TestCloneValue_CopiesAPointerKey(t *testing.T) {
	key := &pair{X: 1}
	copied := cloneValue(map[*pair]string{key: "a"}).(map[*pair]string)
	for copiedKey, value := range copied {
		if copiedKey == key || *copiedKey != *key || value != "a" {
			t.Errorf("expected the key to be a copy of %+v, got %p %+v %q", *key, copiedKey, *copiedKey, value)
		}
	}
	if len(copied) != 1 {
		t.Errorf("expected one entry, got %d", len(copied))
	}
}

func TestCloneValue_KeepsTheTypeOfAContainerPastTheWalkBudget(t *testing.T) {
	keys := make([]map[string]any, operandWalkBudget+1)
	for i := range keys {
		keys[i] = map[string]any{"kid": i}
	}
	copied, ok := cloneValue(keys).([]map[string]any)
	if !ok || len(copied) != len(keys) {
		t.Fatalf("expected a []map[string]any of %d keys, got %T", len(keys), cloneValue(keys))
	}
	keys[0]["kid"] = "written"
	if copied[0]["kid"] == "written" {
		t.Errorf("a write to the original reached the copy")
	}
}

func TestSubordinateStore_PublishesTheMetadataItWasGiven(t *testing.T) {
	given := &Metadata{
		OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
			"contacts":    []string(nil),
			"x_nested":    map[string]any{"absent": map[string]int(nil), "list": []string(nil)},
			"client_name": "ops",
		},
	}
	want, err := json.Marshal(given)
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	intermediate := &IntermediateConfiguration{}
	intermediate.AddSubordinate("https://leaf.example.com", &SubordinateConfiguration{Metadata: given})
	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
	stored, err := cfg.GetSubordinate(context.Background(), "https://leaf.example.com")
	if err != nil {
		t.Fatalf("expected the subordinate, got %v", err)
	}
	got, err := json.Marshal(stored.Metadata)
	if err != nil {
		t.Fatalf("failed to marshal the stored metadata: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("expected the stored metadata to publish what was given, %s, got %s", want, got)
	}
}

func TestPolicyOperators_HoldAnOperandAsEncodingJSONWritesIt(t *testing.T) {
	if _, err := NewAdd(shoutedNames{"a", "b"}); err == nil {
		t.Errorf("expected add to refuse a slice type whose JSON is a string")
	}
	pinned, err := NewValue([]string(nil))
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	if got := marshalled(t, pinned.OperatorValue()); got != "null" {
		t.Errorf("expected a nil slice to be held as encoding/json writes it, null, got %s", got)
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	for name, construct := range map[string]func(any) error{
		"value":   func(v any) error { _, err := NewValue(v); return err },
		"default": func(v any) error { _, err := NewDefault(v); return err },
		"add":     func(v any) error { _, err := NewAdd([]any{v}); return err },
	} {
		if err := construct(cyclic); !errors.Is(err, errUnstorableValue) {
			t.Errorf("expected %s to refuse an operand no copy can hold with the reason, got %v", name, err)
		}
	}
}
