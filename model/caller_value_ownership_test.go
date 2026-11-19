package model

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"sync"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

const ownershipIdentifier = EntityIdentifier("https://leaf.example.com")

type fixedRetriever struct{ subordinate *SubordinateConfiguration }

func (r fixedRetriever) GetSubordinate(context.Context, EntityIdentifier) (*SubordinateConfiguration, error) {
	return r.subordinate, nil
}

func (r fixedRetriever) GetSubordinates(context.Context) (map[EntityIdentifier]*SubordinateConfiguration, error) {
	return map[EntityIdentifier]*SubordinateConfiguration{ownershipIdentifier: r.subordinate}, nil
}

func (r fixedRetriever) GetSubordinateSigners(context.Context) ([]SignerConfiguration, error) {
	return nil, nil
}

func pastTheWalkBudget() []any {
	values := make([]any, operandWalkBudget+1)
	for i := range values {
		values[i] = map[string]any{"v": strconv.Itoa(i)}
	}
	return values
}

func operatorsOver(t *testing.T, operand map[string]any) map[string]MetadataPolicyOperator {
	t.Helper()
	built := map[string]MetadataPolicyOperator{}
	value, err := NewValue(operand)
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	built["value"] = *value
	fallback, err := NewDefault(operand)
	if err != nil {
		t.Fatalf("expected default to build, got %v", err)
	}
	built["default"] = *fallback
	for name, construct := range map[string]func(any) (MetadataPolicyOperator, error){
		"add":         func(v any) (MetadataPolicyOperator, error) { o, err := NewAdd(v); return deref(o), err },
		"one_of":      func(v any) (MetadataPolicyOperator, error) { o, err := NewOneOf(v); return deref(o), err },
		"subset_of":   func(v any) (MetadataPolicyOperator, error) { o, err := NewSubsetOf(v); return deref(o), err },
		"superset_of": func(v any) (MetadataPolicyOperator, error) { o, err := NewSupersetOf(v); return deref(o), err },
	} {
		operator, err := construct([]any{operand})
		if err != nil {
			t.Fatalf("expected %s to build, got %v", name, err)
		}
		built[name] = operator
	}
	return built
}

func TestPolicyOperators_KeepNoContainerTheCallerGave(t *testing.T) {
	operand := map[string]any{"kid": "original", "keys": []any{"a"}}
	for name, operator := range operatorsOver(t, operand) {
		t.Run(name, func(t *testing.T) {
			before, err := json.Marshal(operator.OperatorValue())
			if err != nil {
				t.Fatalf("expected the operand to marshal, got %v", err)
			}
			operand["kid"] = "written"
			operand["keys"].([]any)[0] = "written"
			defer func() {
				operand["kid"] = "original"
				operand["keys"].([]any)[0] = "a"
			}()
			after, err := json.Marshal(operator.OperatorValue())
			if err != nil {
				t.Fatalf("expected the operand to marshal, got %v", err)
			}
			if string(before) != string(after) {
				t.Errorf("a write to the map the caller gave reached the operator: %s became %s", before, after)
			}
		})
	}
}

func TestPolicyOperators_KeepNoContainerTheCallerGavePastTheWalkBudget(t *testing.T) {
	operand := pastTheWalkBudget()
	value, err := NewValue(operand)
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	fallback, err := NewDefault(operand)
	if err != nil {
		t.Fatalf("expected default to build, got %v", err)
	}
	added, err := NewAdd(operand)
	if err != nil {
		t.Fatalf("expected add to build, got %v", err)
	}
	for name, operator := range map[string]MetadataPolicyOperator{"value": *value, "default": *fallback, "add": *added} {
		t.Run(name, func(t *testing.T) {
			operand[operandWalkBudget].(map[string]any)["v"] = "written"
			defer func() { operand[operandWalkBudget].(map[string]any)["v"] = strconv.Itoa(operandWalkBudget) }()
			if got := operator.OperatorValue().([]any)[operandWalkBudget].(map[string]any)["v"]; got != strconv.Itoa(operandWalkBudget) {
				t.Errorf("a write to the slice the caller gave reached the operator: got %v", got)
			}
			handed := operator.OperatorValue().([]any)
			handed[operandWalkBudget].(map[string]any)["v"] = "handed"
			if got := operator.OperatorValue().([]any)[operandWalkBudget].(map[string]any)["v"]; got != strconv.Itoa(operandWalkBudget) {
				t.Errorf("a write to the slice OperatorValue handed out reached the operator: got %v", got)
			}
		})
	}
}

func TestSubordinateStore_KeepsNoValueTheCallerGavePastTheWalkBudget(t *testing.T) {
	contacts := pastTheWalkBudget()
	intermediate := &IntermediateConfiguration{}
	intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{Metadata: &Metadata{
		OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": contacts},
	}})
	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

	contacts[operandWalkBudget].(map[string]any)["v"] = "written"

	stored, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier)
	if err != nil {
		t.Fatalf("expected the subordinate, got %v", err)
	}
	held := (*stored.Metadata.OpenIDRelyingPartyMetadata)["x_param"].([]any)
	if held[operandWalkBudget].(map[string]any)["v"] != strconv.Itoa(operandWalkBudget) {
		t.Errorf("a write to the slice the caller registered reached the store: got %v", held[operandWalkBudget])
	}
	held[operandWalkBudget-1].(map[string]any)["v"] = "handed"
	again, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier)
	if err != nil {
		t.Fatalf("expected the subordinate, got %v", err)
	}
	if got := (*again.Metadata.OpenIDRelyingPartyMetadata)["x_param"].([]any)[operandWalkBudget-1].(map[string]any)["v"]; got != strconv.Itoa(operandWalkBudget-1) {
		t.Errorf("a write to a value GetSubordinate handed out reached the store: got %v", got)
	}
}

func TestSubordinateStore_RebuildsAnOperatorHeldThroughAPointer(t *testing.T) {
	pinned, err := NewValue(map[string]any{"kid": "original"})
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	replacement, err := NewValue(map[string]any{"kid": "written"})
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	intermediate := &IntermediateConfiguration{}
	intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{Policies: MetadataPolicy{
		OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"jwks": {Metadata: []MetadataPolicyOperator{pinned}}},
	}})
	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

	*pinned = *replacement

	stored, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier)
	if err != nil {
		t.Fatalf("expected the subordinate, got %v", err)
	}
	operator := stored.Policies.OpenIDRelyingPartyMetadata["jwks"].Metadata[0]
	if reflect.TypeOf(operator).Kind() == reflect.Pointer {
		t.Errorf("expected the store to hold its own operator, not the caller's pointer %T", operator)
	}
	if got := operator.OperatorValue(); !reflect.DeepEqual(got, map[string]any{"kid": "original"}) {
		t.Errorf("a write through the pointer the caller registered reached the store: got %#v", got)
	}
}

func TestSubordinateStore_KeepsAConsumerOperatorAsItIs(t *testing.T) {
	own := &scopeCarryingOperator{operand: "x"}
	intermediate := &IntermediateConfiguration{}
	intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{Policies: MetadataPolicy{
		OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"x_param": {Metadata: []MetadataPolicyOperator{own}}},
	}})
	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
	stored, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier)
	if err != nil {
		t.Fatalf("expected the subordinate, got %v", err)
	}
	if got := stored.Policies.OpenIDRelyingPartyMetadata["x_param"].Metadata[0]; got != MetadataPolicyOperator(own) {
		t.Errorf("expected an operator type the library does not define to be kept as it is, got %#v", got)
	}
}

func TestSubordinateStore_RefusesAValueThatCannotBeHeldAsJSON(t *testing.T) {
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	unencodable := []any{make(chan int)}

	for name, value := range map[string]any{"a map that holds itself": cyclic, "a channel": unencodable} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewValue(value); err == nil {
				t.Errorf("expected value to refuse an operand no copy can hold")
			}
			if _, err := NewAdd([]any{value}); err == nil {
				t.Errorf("expected add to refuse an operand no copy can hold")
			}

			intermediate := &IntermediateConfiguration{}
			intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"contacts": []any{"ops"}}}})
			intermediate.AddSubordinate("not an identifier", &SubordinateConfiguration{})
			if listed, unlisted := intermediate.listing(); len(listed) != 1 || unlisted != 1 {
				t.Fatalf("the fixture is wrong: expected one listed and one unlisted record, got %v and %d", listed, unlisted)
			}
			intermediate.AddSubordinate("not an identifier", &SubordinateConfiguration{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": value}}})
			if _, unlisted := intermediate.listing(); unlisted != 0 {
				t.Errorf("expected a dropped record to leave the unlisted count, got %d", unlisted)
			}
			intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": value}}})
			cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
			stored, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier)
			if !errors.Is(err, ErrServerError) || stored != nil {
				t.Errorf("expected a subordinate the store cannot hold to be dropped, earlier record included, and answered as a server error, got %v, %v", stored, err)
			}
			if listed, _ := cfg.SubordinateIdentifiers(context.Background()); len(listed) != 0 {
				t.Errorf("expected a dropped subordinate to be left out of the listing, got %v", listed)
			}

			intermediate.FlushCache()
			if _, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier); !errors.Is(err, ErrNotFound) {
				t.Errorf("expected FlushCache to forget the refusal, got %v", err)
			}
			intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": value}}})
			intermediate.AddSubordinate(ownershipIdentifier, &SubordinateConfiguration{})
			if _, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier); err != nil {
				t.Errorf("expected a later storable record to replace the refusal, got %v", err)
			}

			for where, subordinate := range map[string]*SubordinateConfiguration{
				"a key":        {JWKs: josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "x_member": value}}}},
				"an extension": {Metadata: &Metadata{Extensions: map[string]map[string]any{"x_type": {"x_param": value}}}},
			} {
				intermediate.AddSubordinate(ownershipIdentifier, subordinate)
				if _, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier); !errors.Is(err, ErrServerError) {
					t.Errorf("expected %s the store cannot hold to drop the record, got %v", where, err)
				}
			}

			retrieved := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{}, MetadataRetriever: fixedRetriever{subordinate: &SubordinateConfiguration{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": value}}}}}
			if _, err := retrieved.GetSubordinate(context.Background(), ownershipIdentifier); !errors.Is(err, ErrServerError) {
				t.Errorf("expected a Retriever record the store cannot hold to be refused as a server error, got %v", err)
			}
		})
	}
}

type ownershipScenario struct {
	subordinate  func() *SubordinateConfiguration
	write        func(i int)
	viaRetriever bool
	reads        int
}

func ownershipScenarios(t *testing.T) map[string]ownershipScenario {
	operand := map[string]any{"kid": "original"}
	pinned, err := NewValue(operand)
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	pointed, err := NewValue(map[string]any{"kid": "original"})
	if err != nil {
		t.Fatalf("expected value to build, got %v", err)
	}
	alternates := []Value{}
	for i := range 2 {
		alternate, err := NewValue(map[string]any{"kid": strconv.Itoa(i)})
		if err != nil {
			t.Fatalf("expected value to build, got %v", err)
		}
		alternates = append(alternates, *alternate)
	}
	large := pastTheWalkBudget()
	last := large[len(large)-1].(map[string]any)
	return map[string]ownershipScenario{
		"an operand map the caller keeps writing": {
			subordinate: func() *SubordinateConfiguration {
				return &SubordinateConfiguration{Policies: MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"jwks": {Metadata: []MetadataPolicyOperator{*pinned}}}}}
			},
			write:        func(i int) { operand["x"+strconv.Itoa(i%8)] = i },
			viaRetriever: true,
			reads:        2000,
		},
		"an operator pointer the caller keeps rewriting": {
			subordinate: func() *SubordinateConfiguration {
				return &SubordinateConfiguration{Policies: MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"jwks": {Metadata: []MetadataPolicyOperator{pointed}}}}}
			},
			write: func(i int) { *pointed = alternates[i%2] },
			reads: 2000,
		},
		"a metadata array past the walk budget the caller keeps writing": {
			subordinate: func() *SubordinateConfiguration {
				return &SubordinateConfiguration{Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"x_param": large}}}
			},
			write: func(i int) { last["x"+strconv.Itoa(i%8)] = i },
			reads: 5,
		},
	}
}

func readStoreWhileTheCallerWrites(t *testing.T, scenario ownershipScenario) {
	cfg := ServerConfiguration{IntermediateConfiguration: &IntermediateConfiguration{}}
	if scenario.viaRetriever {
		cfg.MetadataRetriever = fixedRetriever{subordinate: scenario.subordinate()}
	} else {
		cfg.IntermediateConfiguration.AddSubordinate(ownershipIdentifier, scenario.subordinate())
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				scenario.write(i)
			}
		}
	})
	for range scenario.reads {
		stored, err := cfg.GetSubordinate(context.Background(), ownershipIdentifier)
		if err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("expected the subordinate, got %v", err)
		}
		if _, err := json.Marshal(stored.Policies); err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("expected the policy to marshal, got %v", err)
		}
		if _, err := json.Marshal(stored.Metadata); err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("expected the metadata to marshal, got %v", err)
		}
	}
	close(done)
	wg.Wait()
}

func TestSubordinateStore_ReadsNothingTheCallerWritesConcurrently(t *testing.T) {
	for name, scenario := range ownershipScenarios(t) {
		t.Run(name, func(t *testing.T) {
			readStoreWhileTheCallerWrites(t, scenario)
		})
	}
}

const crashScenarioVariable = "GOF_OWNERSHIP_CRASH_SCENARIO"

func TestSubordinateStore_ACallerWriteCannotCrashTheProcess(t *testing.T) {
	if name := os.Getenv(crashScenarioVariable); name != "" {
		readStoreWhileTheCallerWrites(t, ownershipScenarios(t)[name])
		return
	}
	for name := range ownershipScenarios(t) {
		t.Run(name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestSubordinateStore_ACallerWriteCannotCrashTheProcess$", "-test.count=1")
			command.Env = append(os.Environ(), crashScenarioVariable+"="+name)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("expected the store to share nothing a caller writes, so no write can crash the process, got %v:\n%.2000s", err, output)
			}
		})
	}
}
