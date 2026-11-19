package model

import (
	"errors"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"math"
	"reflect"
	"strings"
	"testing"
)

type nanHolder struct{ F float64 }

func uncopyable() nanHolder { return nanHolder{F: math.NaN()} }

func isTheUncopyableValue(value any) bool {
	held, ok := value.(nanHolder)
	return ok && math.IsNaN(held.F)
}

type resolvesToOperator struct{ resolved any }

func (o resolvesToOperator) String() string                            { return "x_resolves_to" }
func (o resolvesToOperator) Resolve(any) (any, error)                  { return o.resolved, nil }
func (o resolvesToOperator) ResolutionHierarchy() int                  { return 98 }
func (o resolvesToOperator) Merge(any) (MetadataPolicyOperator, error) { return o, nil }
func (o resolvesToOperator) OperatorValue() any                        { return o.resolved }
func (o resolvesToOperator) ToSlice(string) MetadataPolicyOperator     { return o }
func (o resolvesToOperator) CheckForConflict(func(reflect.Type) (MetadataPolicyOperator, bool)) error {
	return nil
}

func TestApplyPolicy_RefusesAResolvedValueItCannotCopy(t *testing.T) {
	subject := EntityStatement{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"client_name": "ops"}}}
	policy := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
		"x_param": {Metadata: []MetadataPolicyOperator{resolvesToOperator{resolved: uncopyable()}}},
	}}

	result, err := ApplyPolicy(subject, policy)

	if err == nil {
		t.Fatalf("expected a value the library cannot copy to be refused, got x_param %#v", (*result.Metadata.OpenIDRelyingPartyMetadata)["x_param"])
	}
	if !errors.Is(err, errUnstorableValue) || !strings.Contains(err.Error(), "x_param") {
		t.Errorf("expected the refusal to wrap errUnstorableValue and name x_param, got %v", err)
	}
}

func TestApplyPolicy_RefusesASubjectItCannotCopy(t *testing.T) {
	tests := map[string]func(*EntityStatement){
		"a metadata parameter under the policy": func(s *EntityStatement) {
			(*s.Metadata.OpenIDRelyingPartyMetadata)["x_held"] = uncopyable()
		},
		"a metadata parameter of an entity type without a policy": func(s *EntityStatement) {
			s.Metadata.FederationMetadata = &FederationMetadata{"x_held": uncopyable()}
		},
		"an extension entity type": func(s *EntityStatement) {
			s.Metadata.Extensions = map[string]map[string]any{"x_type": {"x_held": uncopyable()}}
		},
		"a key of the entity": func(s *EntityStatement) {
			s.JWKs.Keys = []map[string]any{{"kty": "EC", "x_held": uncopyable()}}
		},
		"a key of a trust mark owner": func(s *EntityStatement) {
			s.TrustMarkOwners = map[string]TrustMarkOwner{"https://tm.example.com": {JWKs: josemodel.Jwks{Keys: []map[string]any{{"x_held": uncopyable()}}}}}
		},
		"a parameter past the operand walk budget": func(s *EntityStatement) {
			(*s.Metadata.OpenIDRelyingPartyMetadata)["x_bulk"] = make([]any, operandWalkBudget+1)
			(*s.Metadata.OpenIDRelyingPartyMetadata)["x_held"] = uncopyable()
		},
		"a claim of a trust mark owner": func(s *EntityStatement) {
			s.TrustMarkOwners = map[string]TrustMarkOwner{"https://tm.example.com": {AdditionalClaims: map[string]any{"x_held": uncopyable()}}}
		},
	}
	policy := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
		"client_name": {Metadata: []MetadataPolicyOperator{Essential{operatorValue: true}}},
	}}
	for name, place := range tests {
		t.Run(name, func(t *testing.T) {
			subject := EntityStatement{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"client_name": "ops"}}}
			place(&subject)

			_, err := ApplyPolicy(subject, policy)

			if !errors.Is(err, errUnstorableValue) {
				t.Errorf("expected a subject holding a value the library cannot copy to be refused with errUnstorableValue, got %v", err)
			}
		})
	}
}

func metadataWithOneUncopyableValue() (*Metadata, *nanHolder) {
	pointed := &nanHolder{F: math.NaN()}
	return &Metadata{
		OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
			"client_name": "ops",
			"contacts":    []any{"ops@example.com"},
			"x_held":      uncopyable(),
			"x_pointed":   pointed,
			"x_nested":    map[string]any{"list": []any{"nested@example.com"}, "held": uncopyable()},
		},
		Extensions: map[string]map[string]any{"x_type": {
			"list":   []any{"extension@example.com"},
			"x_held": uncopyable(),
		}},
	}, pointed
}

func expectUncopyableKeptAndTheRestCopied(t *testing.T, input, got *Metadata, pointed *nanHolder) {
	t.Helper()
	before := marshalled(t, map[string]any{
		"contacts":  (*input.OpenIDRelyingPartyMetadata)["contacts"],
		"list":      (*input.OpenIDRelyingPartyMetadata)["x_nested"].(map[string]any)["list"],
		"extension": input.Extensions["x_type"]["list"],
	})
	if got == nil || got.OpenIDRelyingPartyMetadata == nil {
		t.Fatalf("expected the relying party metadata to be kept, got %#v", got)
	}
	parameters := *got.OpenIDRelyingPartyMetadata
	if parameters["client_name"] != "ops" {
		t.Errorf("expected client_name to be kept, got %#v", parameters["client_name"])
	}
	if !isTheUncopyableValue(parameters["x_held"]) {
		t.Errorf("expected the value the library cannot copy to be kept as it was, got %#v", parameters["x_held"])
	}
	if parameters["x_pointed"] != pointed {
		t.Errorf("expected the pointer the library cannot copy to be kept as it was, got %#v", parameters["x_pointed"])
	}
	nested, ok := parameters["x_nested"].(map[string]any)
	if !ok || !isTheUncopyableValue(nested["held"]) {
		t.Fatalf("expected the nested value the library cannot copy to be kept as it was, got %#v", parameters["x_nested"])
	}
	extension, ok := got.Extensions["x_type"]
	if !ok || !isTheUncopyableValue(extension["x_held"]) {
		t.Fatalf("expected the extension value the library cannot copy to be kept as it was, got %#v", got.Extensions)
	}
	if !reflect.DeepEqual(parameters["contacts"], []any{"ops@example.com"}) || !reflect.DeepEqual(nested["list"], []any{"nested@example.com"}) || !reflect.DeepEqual(extension["list"], []any{"extension@example.com"}) {
		t.Fatalf("expected the values the library can copy to be kept, got %#v and %#v", parameters, extension)
	}
	writeIntoResolved(parameters["contacts"])
	writeIntoResolved(nested["list"])
	writeIntoResolved(extension["list"])
	after := marshalled(t, map[string]any{
		"contacts":  (*input.OpenIDRelyingPartyMetadata)["contacts"],
		"list":      (*input.OpenIDRelyingPartyMetadata)["x_nested"].(map[string]any)["list"],
		"extension": input.Extensions["x_type"]["list"],
	})
	if after != before {
		t.Errorf("[#156] a write to a value the library can copy reached the input:\nwant %s\ngot  %s", before, after)
	}
}

func TestMetadataForEntityTypes_KeepsAValueItCannotCopyAndCopiesTheRest(t *testing.T) {
	input, pointed := metadataWithOneUncopyableValue()

	got := input.ForEntityTypes(nil)

	expectUncopyableKeptAndTheRestCopied(t, input, got, pointed)
}

func TestApplySuperiorMetadata_KeepsAValueItCannotCopyAndCopiesTheRest(t *testing.T) {
	t.Run("from the subject", func(t *testing.T) {
		input, pointed := metadataWithOneUncopyableValue()

		got := ApplySuperiorMetadata(input, nil)

		expectUncopyableKeptAndTheRestCopied(t, input, got, pointed)
	})
	t.Run("from the superior", func(t *testing.T) {
		input, pointed := metadataWithOneUncopyableValue()
		subject := &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{}, Extensions: map[string]map[string]any{"x_type": {}}}

		got := ApplySuperiorMetadata(subject, input)

		expectUncopyableKeptAndTheRestCopied(t, input, got, pointed)
	})
}

func TestMetadataForEntityTypes_KeepsAnEntityTypePastTheBudgetThatItCannotCopy(t *testing.T) {
	bulk := make([]any, operandWalkBudget+1)
	input := &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
		"client_name": "ops",
		"x_bulk":      bulk,
		"x_held":      uncopyable(),
	}}

	got := input.ForEntityTypes(nil)

	if got == nil || got.OpenIDRelyingPartyMetadata == nil {
		t.Fatalf("expected the relying party metadata to be kept, got %#v", got)
	}
	parameters := *got.OpenIDRelyingPartyMetadata
	if parameters["client_name"] != "ops" || !isTheUncopyableValue(parameters["x_held"]) {
		t.Errorf("expected every parameter to be kept as it was, got client_name %#v and x_held %#v", parameters["client_name"], parameters["x_held"])
	}
	if kept, ok := parameters["x_bulk"].([]any); !ok || len(kept) != len(bulk) {
		t.Errorf("expected x_bulk to be kept with %d elements", len(bulk))
	}
}
