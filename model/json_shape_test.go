package model

import (
	"context"
	"encoding/json"
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
	}
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

func TestJSONShape_KeepsWhatIsAlreadyJSON(t *testing.T) {
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
			if got := jsonShape(tc.value); !reflect.DeepEqual(got, tc.value) {
				t.Errorf("expected %#v to be kept as it is, got %#v", tc.value, got)
			}
		})
	}
}

func TestJSONShape_GivesUpOnAValuePastTheWalkBudget(t *testing.T) {
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = jsonShape(cyclic)
		_ = jsonShape(nested)
		_ = jsonShape(shared)
		_ = cloneValue(cyclic)
		_ = cloneValue(shared)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("normalising a value that refers to itself did not finish")
	}
}

func TestJSONShape_WritesANilPointerAsNull(t *testing.T) {
	var contacts *[]string
	if got := jsonShape(contacts); got != nil {
		t.Errorf("expected a nil pointer to be held as JSON null, got %#v", got)
	}
	if got := jsonShape([]any{contacts}); !reflect.DeepEqual(got, []any{nil}) {
		t.Errorf("expected a nil pointer in an array to be held as JSON null, got %#v", got)
	}
	if _, err := NewDefault(contacts); err == nil {
		t.Errorf("expected default to refuse an operand whose JSON is null, as it refuses null itself")
	}
}
