package model

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

type ownedSubordinate struct {
	configuration *SubordinateConfiguration
	jwksOperand   map[string]any
	addOperand    map[string]any
}

func newOwnedSubordinate(t *testing.T) ownedSubordinate {
	t.Helper()
	jwksOperand := map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "kid": "pinned"}}}
	pinned, err := NewValue(jwksOperand)
	if err != nil {
		t.Fatalf("expected the value operator to build, got %v", err)
	}
	addOperand := map[string]any{"name": "ops"}
	added, err := NewAdd([]any{addOperand})
	if err != nil {
		t.Fatalf("expected the add operator to build, got %v", err)
	}
	var parsed MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"grant_types":{"subset_of":["authorization_code"],"superset_of":["authorization_code"],"default":["authorization_code"]},"token_endpoint_auth_method":{"one_of":["private_key_jwt"],"essential":true},"x_param":{"x_operator":1}},"x_type":{"x_param":{"value":"x"}}}`), &parsed); err != nil {
		t.Fatalf("expected the policy to parse, got %v", err)
	}
	parsed.OpenIDRelyingPartyMetadata["jwks"] = PolicyOperators{Metadata: []MetadataPolicyOperator{*pinned}}
	parsed.OpenIDRelyingPartyMetadata["contacts"] = PolicyOperators{Metadata: []MetadataPolicyOperator{*added}}
	pathLength := 2
	return ownedSubordinate{
		configuration: &SubordinateConfiguration{
			Policies: parsed,
			JWKs: josemodel.Jwks{Keys: []map[string]any{
				{"kty": "EC", "crv": "P-256", "kid": "registered", "x5c": []any{"certificate"}},
			}},
			SignerConfiguration: &SignerConfiguration{KeyID: "signer", Algorithm: "ES256"},
			Constraints: &Constraints{
				MaxPathLength:      &pathLength,
				NamingConstraints:  &NamingConstraints{Permitted: []string{"example.com"}, Excluded: []string{"bad.example.com"}},
				AllowedEntityTypes: []string{"openid_relying_party"},
			},
			Metadata: &Metadata{
				OAuthResourceMetadata: &OAuthResourceMetadata{"api_resources": []any{"https://api.example.com/a"}},
				Extensions:            map[string]map[string]any{"x_type": {"x_param": []any{"x"}}},
			},
		},
		jwksOperand: jwksOperand,
		addOperand:  addOperand,
	}
}

func snapshot(t *testing.T, subordinate *SubordinateConfiguration) string {
	t.Helper()
	policy, err := json.Marshal(subordinate.Policies)
	if err != nil {
		t.Fatalf("expected the policy to marshal, got %v", err)
	}
	keys, err := json.Marshal(subordinate.JWKs.Keys)
	if err != nil {
		t.Fatalf("expected the keys to marshal, got %v", err)
	}
	constraints, err := json.Marshal(subordinate.Constraints)
	if err != nil {
		t.Fatalf("expected the constraints to marshal, got %v", err)
	}
	keys = append(keys, constraints...)
	metadata, err := json.Marshal(subordinate.Metadata)
	if err != nil {
		t.Fatalf("expected the metadata to marshal, got %v", err)
	}
	keys = append(keys, metadata...)
	signer := "<none>"
	if subordinate.SignerConfiguration != nil {
		signer = subordinate.SignerConfiguration.KeyID + "/" + subordinate.SignerConfiguration.Algorithm
	}
	return string(policy) + " " + string(keys) + " " + signer + " " + string(mustJSON(t, subordinate.Policies.OpenIDRelyingPartyMetadata["x_param"].Unrecognised))
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("expected the value to marshal, got %v", err)
	}
	return encoded
}

func writeThrough(owned ownedSubordinate) []struct {
	name  string
	write func(*SubordinateConfiguration)
} {
	return []struct {
		name  string
		write func(*SubordinateConfiguration)
	}{
		{name: "a key member", write: func(s *SubordinateConfiguration) { s.JWKs.Keys[0]["kid"] = "rotated" }},
		{name: "a nested key member", write: func(s *SubordinateConfiguration) { s.JWKs.Keys[0]["x5c"].([]any)[0] = "forged" }},
		{name: "a key in the slice", write: func(s *SubordinateConfiguration) { s.JWKs.Keys[0] = map[string]any{"kid": "swapped"} }},
		{name: "the keys cleared", write: func(s *SubordinateConfiguration) { clear(s.JWKs.Keys[0]) }},
		{name: "an object operand", write: func(s *SubordinateConfiguration) {
			owned.jwksOperand["keys"] = []any{}
			owned.addOperand["name"] = "attacker"
		}},
		{name: "an operator in a parameter", write: func(s *SubordinateConfiguration) {
			s.Policies.OpenIDRelyingPartyMetadata["grant_types"].Metadata[0] = Essential{}
		}},
		{name: "a parameter of a built-in type", write: func(s *SubordinateConfiguration) {
			delete(s.Policies.OpenIDRelyingPartyMetadata, "token_endpoint_auth_method")
		}},
		{name: "an unrecognised operator name", write: func(s *SubordinateConfiguration) {
			s.Policies.OpenIDRelyingPartyMetadata["x_param"].Unrecognised[0] = "renamed"
		}},
		{name: "an extension type's parameter", write: func(s *SubordinateConfiguration) {
			s.Policies.Extensions["x_type"]["x_added"] = PolicyOperators{}
		}},
		{name: "the signer", write: func(s *SubordinateConfiguration) { s.SignerConfiguration.KeyID = "other" }},
		{name: "a metadata parameter", write: func(s *SubordinateConfiguration) {
			(*s.Metadata.OAuthResourceMetadata)["api_resources"].([]any)[0] = "https://attacker.example.com"
		}},
		{name: "an allowed entity type", write: func(s *SubordinateConfiguration) { s.Constraints.AllowedEntityTypes[0] = "openid_provider" }},
		{name: "a permitted name", write: func(s *SubordinateConfiguration) {
			s.Constraints.NamingConstraints.Permitted[0] = "attacker.example.com"
		}},
		{name: "an excluded name", write: func(s *SubordinateConfiguration) { s.Constraints.NamingConstraints.Excluded[0] = "nothing.example.com" }},
		{name: "the max path length", write: func(s *SubordinateConfiguration) { *s.Constraints.MaxPathLength = 99 }},
		{name: "an extension type's metadata", write: func(s *SubordinateConfiguration) {
			s.Metadata.Extensions["x_type"]["x_added"] = "forged"
		}},
	}
}

func TestSubordinateStore_ACallerWriteToWhatItRegisteredDoesNotReachTheStore(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	for _, tc := range writeThrough(newOwnedSubordinate(t)) {
		t.Run(tc.name, func(t *testing.T) {
			owned := newOwnedSubordinate(t)
			intermediate := &IntermediateConfiguration{}
			intermediate.AddSubordinate(identifier, owned.configuration)
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
			before, err := cfg.GetSubordinate(context.Background(), identifier)
			if err != nil {
				t.Fatalf("expected the subordinate, got %v", err)
			}
			expected := snapshot(t, before)

			for _, step := range writeThrough(owned) {
				if step.name == tc.name {
					step.write(owned.configuration)
				}
			}

			after, err := cfg.GetSubordinate(context.Background(), identifier)
			if err != nil {
				t.Fatalf("expected the subordinate, got %v", err)
			}
			if got := snapshot(t, after); got != expected {
				t.Errorf("a write to %s after AddSubordinate reached the store:\nwant %s\ngot  %s", tc.name, expected, got)
			}
		})
	}
}

func TestSubordinateStore_ACallerWriteToWhatItWasGivenDoesNotReachTheStore(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	readers := []struct {
		name string
		read func(*testing.T, ServerConfiguration) *SubordinateConfiguration
	}{
		{name: "GetSubordinate", read: func(t *testing.T, cfg ServerConfiguration) *SubordinateConfiguration {
			subordinate, err := cfg.GetSubordinate(context.Background(), identifier)
			if err != nil {
				t.Fatalf("expected the subordinate, got %v", err)
			}
			return subordinate
		}},
		{name: "GetSubordinates", read: func(t *testing.T, cfg ServerConfiguration) *SubordinateConfiguration {
			subordinates, err := cfg.GetSubordinates(context.Background())
			if err != nil {
				t.Fatalf("expected the subordinates, got %v", err)
			}
			return subordinates[identifier]
		}},
	}

	for _, reader := range readers {
		for _, tc := range writeThrough(newOwnedSubordinate(t)) {
			if tc.name == "an object operand" {
				continue
			}
			t.Run(reader.name+": "+tc.name, func(t *testing.T) {
				intermediate := &IntermediateConfiguration{}
				intermediate.AddSubordinate(identifier, newOwnedSubordinate(t).configuration)
				cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
				given := reader.read(t, cfg)
				expected := snapshot(t, given)

				tc.write(given)

				if got := snapshot(t, reader.read(t, cfg)); got != expected {
					t.Errorf("a write to %s of what %s returned reached the store:\nwant %s\ngot  %s", tc.name, reader.name, expected, got)
				}
			})
		}
	}
}

func TestSubordinateStore_ARetrieverResultIsCachedAsItsOwnCopy(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")

	t.Run("a later write to what the retriever returned", func(t *testing.T) {
		owned := newOwnedSubordinate(t)
		retriever := &cacheRetriever{subordinate: owned.configuration}
		cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{SubordinateCacheTime: time.Hour}, MetadataRetriever: retriever}
		first, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		expected := snapshot(t, first)

		owned.configuration.JWKs.Keys[0]["kid"] = "rotated"
		owned.jwksOperand["keys"] = []any{}

		cached, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		if retriever.calls != 1 {
			t.Fatalf("expected the second read to come from the cache, got %d retriever calls", retriever.calls)
		}
		if got := snapshot(t, cached); got != expected {
			t.Errorf("a write to the retriever's own value reached the cache:\nwant %s\ngot  %s", expected, got)
		}
	})

	t.Run("a write to what GetSubordinate returned from the retriever", func(t *testing.T) {
		retriever := &cacheRetriever{subordinate: newOwnedSubordinate(t).configuration}
		cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{SubordinateCacheTime: time.Hour}, MetadataRetriever: retriever}
		first, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		expected := snapshot(t, first)

		clear(first.JWKs.Keys[0])
		first.SignerConfiguration.KeyID = "other"

		cached, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		if got := snapshot(t, cached); got != expected {
			t.Errorf("a write to the returned value reached the cache:\nwant %s\ngot  %s", expected, got)
		}
	})

	t.Run("a write to what GetSubordinate returned from the cache", func(t *testing.T) {
		retriever := &cacheRetriever{subordinate: newOwnedSubordinate(t).configuration}
		cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{SubordinateCacheTime: time.Hour}, MetadataRetriever: retriever}
		first, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		expected := snapshot(t, first)
		fromCache, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}

		clear(fromCache.JWKs.Keys[0])

		again, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		if retriever.calls != 1 {
			t.Fatalf("expected every read after the first to come from the cache, got %d retriever calls", retriever.calls)
		}
		if got := snapshot(t, again); got != expected {
			t.Errorf("a write to a value served from the cache reached the cache:\nwant %s\ngot  %s", expected, got)
		}
	})

	t.Run("with no cache, the retriever's value is still not handed back", func(t *testing.T) {
		owned := newOwnedSubordinate(t)
		retriever := &cacheRetriever{subordinate: owned.configuration}
		cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{}, MetadataRetriever: retriever}
		given, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		given.JWKs.Keys[0]["kid"] = "rotated"
		if owned.configuration.JWKs.Keys[0]["kid"] != "registered" {
			t.Errorf("a write to the returned value reached the retriever's own value")
		}
		if owned.configuration.CachedAt != 0 {
			t.Errorf("expected the retriever's value to be left unchanged, got CachedAt %d", owned.configuration.CachedAt)
		}
	})
}

func TestSubordinateStore_TheCopyKeepsTheShapeItWasGiven(t *testing.T) {
	owned := newOwnedSubordinate(t)
	misplaced := map[string]PolicyOperators{"organization_name": {Metadata: []MetadataPolicyOperator{Value{operatorValue: "Pinned"}}}}
	owned.configuration.Policies.Extensions["federation_entity"] = misplaced
	owned.configuration.Metadata.Extensions["federation_entity"] = map[string]any{"organization_name": "Pinned"}
	original := owned.configuration

	copied := original.clone()

	if !reflect.DeepEqual(copied, original) {
		t.Errorf("expected the copy to equal the original:\nwant %#v\ngot  %#v", original, copied)
	}
	if copied.Policies.FederationMetadata != nil || copied.Metadata.FederationMetadata != nil {
		t.Errorf("expected an Extensions entry under a built-in name to stay in Extensions, so MarshalJSON still refuses it")
	}
	if copied.Metadata == original.Metadata {
		t.Errorf("expected the copy to hold its own Metadata")
	}
	if copied.SignerConfiguration == original.SignerConfiguration {
		t.Errorf("expected the copy to hold its own SignerConfiguration")
	}

	empty := &SubordinateConfiguration{}
	if copiedEmpty := empty.clone(); !reflect.DeepEqual(copiedEmpty, empty) {
		t.Errorf("expected an empty configuration to copy as empty, got %#v", copiedEmpty)
	}
}

type ownOperator struct{ operand map[string]any }

func (o ownOperator) String() string                            { return "x_own" }
func (o ownOperator) Resolve(value any) (any, error)            { return value, nil }
func (o ownOperator) ResolutionHierarchy() int                  { return 99 }
func (o ownOperator) Merge(any) (MetadataPolicyOperator, error) { return o, nil }
func (o ownOperator) OperatorValue() any                        { return o.operand }
func (o ownOperator) ToSlice(string) MetadataPolicyOperator     { return o }
func (o ownOperator) CheckForConflict(func(reflect.Type) (MetadataPolicyOperator, bool)) error {
	return nil
}

func TestSubordinateStore_AnOperatorTypeTheLibraryDoesNotDefineIsKeptAsGiven(t *testing.T) {
	operator := ownOperator{operand: map[string]any{"a": 1}}
	original := &SubordinateConfiguration{Policies: MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"contacts": {Metadata: []MetadataPolicyOperator{operator}}}}}

	copied := original.clone()

	if !reflect.DeepEqual(copied.Policies.OpenIDRelyingPartyMetadata["contacts"].Metadata, []MetadataPolicyOperator{operator}) {
		t.Errorf("expected a consumer's own operator to be carried over, got %#v", copied.Policies.OpenIDRelyingPartyMetadata["contacts"].Metadata)
	}
}

func TestSubordinateStore_ACallerWritingWhileTheStoreIsReadDoesNotRace(t *testing.T) {
	const identifier = EntityIdentifier("https://leaf.example.com")
	owned := newOwnedSubordinate(t)
	intermediate := &IntermediateConfiguration{}
	intermediate.AddSubordinate(identifier, owned.configuration)
	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 200 {
			owned.configuration.JWKs.Keys[0]["kid"] = i
			owned.jwksOperand["keys"] = []any{i}
		}
	})
	for range 200 {
		subordinate, err := cfg.GetSubordinate(context.Background(), identifier)
		if err != nil {
			t.Fatalf("expected the subordinate, got %v", err)
		}
		if subordinate.JWKs.Keys[0]["kid"] != "registered" {
			t.Fatalf("expected the registered kid, got %v", subordinate.JWKs.Keys[0]["kid"])
		}
		if _, err := json.Marshal(subordinate.Policies); err != nil {
			t.Fatalf("expected the policy to marshal, got %v", err)
		}
	}
	wg.Wait()
}

type identifierRetriever struct {
	cacheRetriever
	subordinates map[EntityIdentifier]*SubordinateConfiguration
	err          error
}

func (r *identifierRetriever) GetSubordinates(context.Context) (map[EntityIdentifier]*SubordinateConfiguration, error) {
	return r.subordinates, r.err
}

func TestServerConfiguration_SubordinateIdentifiers(t *testing.T) {
	want := []EntityIdentifier{"https://a.example.com", "https://b.example.com", "https://c.example.com"}

	t.Run("the in-memory store, in sorted order", func(t *testing.T) {
		intermediate := &IntermediateConfiguration{}
		for _, identifier := range []EntityIdentifier{want[2], want[0], want[1]} {
			intermediate.AddSubordinate(identifier, &SubordinateConfiguration{})
		}
		got, err := (&ServerConfiguration{IntermediateConfiguration: intermediate}).SubordinateIdentifiers(context.Background())
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("expected %v, got %v (%v)", want, got, err)
		}
	})

	t.Run("a write to a returned listing does not reach the next one", func(t *testing.T) {
		intermediate := &IntermediateConfiguration{}
		for _, identifier := range want {
			intermediate.AddSubordinate(identifier, &SubordinateConfiguration{})
		}
		cfg := &ServerConfiguration{IntermediateConfiguration: intermediate}
		for range 3 {
			got, err := cfg.SubordinateIdentifiers(context.Background())
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("expected %v, got %v (%v)", want, got, err)
			}
			got[0] = "https://written.example.com"
		}
	})

	t.Run("an empty store", func(t *testing.T) {
		got, err := (&ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{}}).SubordinateIdentifiers(context.Background())
		if err != nil || len(got) != 0 {
			t.Errorf("expected no identifiers, got %v (%v)", got, err)
		}
	})

	t.Run("the retriever's subordinates, in sorted order, ahead of the in-memory store", func(t *testing.T) {
		intermediate := &IntermediateConfiguration{}
		intermediate.AddSubordinate("https://cached.example.com", &SubordinateConfiguration{})
		retriever := &identifierRetriever{subordinates: map[EntityIdentifier]*SubordinateConfiguration{want[1]: nil, want[2]: nil, want[0]: nil}}
		got, err := (&ServerConfiguration{IntermediateConfiguration: intermediate, MetadataRetriever: retriever}).SubordinateIdentifiers(context.Background())
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("expected %v, got %v (%v)", want, got, err)
		}
	})

	t.Run("a retriever error is returned as it is", func(t *testing.T) {
		failure := NewTemporarilyUnavailableError("store throttled")
		retriever := &identifierRetriever{err: failure}
		_, err := (&ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{}, MetadataRetriever: retriever}).SubordinateIdentifiers(context.Background())
		if !errors.Is(err, ErrTemporarilyUnavailable) {
			t.Errorf("expected the retriever's error class, got %v", err)
		}
	})
}
