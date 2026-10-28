package model

import (
	"math"
	"testing"
	"time"
)

func selfReferencingOperands() map[string]any {
	slice := make([]any, 1)
	slice[0] = slice
	object := map[string]any{}
	object["self"] = object
	twice := map[string]any{}
	twice["a"] = twice
	twice["b"] = twice
	return map[string]any{
		"a slice holding itself":            slice,
		"an object holding itself":          object,
		"an object holding itself twice":    twice,
		"a slice holding a looping object":  []any{"x", object},
		"an object holding a looping slice": map[string]any{"k": slice},
	}
}

func sharedOperand(levels int) any {
	var value any = "leaf"
	for range levels {
		value = []any{value, value}
	}
	return value
}

func TestPolicyOperands_ASelfReferencingOperandIsUnmatchableNotFatal(t *testing.T) {
	for name, value := range selfReferencingOperands() {
		t.Run(name, func(t *testing.T) {
			if _, keyed := canonicalOperandKey(value); keyed {
				t.Errorf("expected a value with no end to have no canonical key")
			}
			if operandCanMatch(value) {
				t.Errorf("expected a value with no end to match nothing")
			}
			if operandsEqual(value, value) {
				t.Errorf("expected a value with no end not to equal even itself")
			}
			if got := DeduplicateSlice([]any{value, value, "kept"}); len(got) != 3 {
				t.Errorf("expected an unmatchable value never to be merged away, got %d entries", len(got))
			}
			if newOperandSet([]any{value}).contains(value) {
				t.Errorf("expected a set never to report holding an unmatchable value")
			}
		})
	}
}

func TestPolicyOperands_SharedStructureIsWalkedWithinTheBudget(t *testing.T) {
	value := sharedOperand(60)
	done := make(chan struct{})
	go func() {
		defer close(done)
		canonicalOperandKey(value)
		operandCanMatch(value)
		operandHash(value)
		DeduplicateSlice([]any{value, value})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a value sharing one member 60 levels deep was walked path by path, 2^60 times")
	}
}

func TestPolicyOperands_TheWalkBudgetIsExact(t *testing.T) {
	tests := map[string]struct {
		members int
		keyed   bool
	}{
		"a slice whose nodes fill the budget": {members: operandWalkBudget - 1, keyed: true},
		"a slice one node past the budget":    {members: operandWalkBudget, keyed: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			value := make([]any, tc.members)
			for i := range value {
				value[i] = "m"
			}
			if _, keyed := canonicalOperandKey(value); keyed != tc.keyed {
				t.Errorf("expected keyed %v for %d members and the slice itself, got %v", tc.keyed, tc.members, keyed)
			}
			if operandCanMatch(value) != tc.keyed {
				t.Errorf("expected matchable %v, got %v", tc.keyed, !tc.keyed)
			}
		})
	}
}

type hashedRecord struct {
	Name  string
	Score float64
	inner *hashedRecord
}

func TestOperandHash_EqualValuesHashEqually(t *testing.T) {
	inf := math.Inf(1)
	negativeZero := math.Copysign(0, -1)
	ordered := map[string]any{}
	reversed := map[string]any{}
	for i := range 32 {
		ordered[string(rune('a'+i%26))+string(rune('a'+i/26))] = i
	}
	keys := make([]string, 0, len(ordered))
	for key := range ordered {
		keys = append(keys, key)
	}
	for i := len(keys) - 1; i >= 0; i-- {
		reversed[keys[i]] = ordered[keys[i]]
	}

	tests := map[string][2]any{
		"slices holding infinity":          {[]any{inf, 1}, []any{inf, 1}},
		"negative and positive zero":       {[]any{inf, negativeZero}, []any{inf, 0.0}},
		"maps filled in different orders":  {map[string]any{"m": ordered, "i": inf}, map[string]any{"i": inf, "m": reversed}},
		"invalid UTF-8 strings":            {[]any{"\xff", 1}, []any{"\xff", 1}},
		"structs with unexported pointers": {hashedRecord{Name: "n", Score: inf, inner: &hashedRecord{Name: "i"}}, hashedRecord{Name: "n", Score: inf, inner: &hashedRecord{Name: "i"}}},
		"pointers to equal values":         {&hashedRecord{Name: "p", Score: inf}, &hashedRecord{Name: "p", Score: inf}},
		"complex values":                   {complex(inf, negativeZero), complex(inf, 0)},
	}

	for name, pair := range tests {
		t.Run(name, func(t *testing.T) {
			if !operandsEqual(pair[0], pair[1]) {
				t.Fatalf("the fixture is wrong: the two values are not equal operands")
			}
			if operandHash(pair[0]) != operandHash(pair[1]) {
				t.Errorf("two equal operands hashed differently, so a deduplication can keep both")
			}
			if got := DeduplicateSlice([]any{pair[0], pair[1]}); len(got) != 1 {
				t.Errorf("expected two equal operands to deduplicate to one, got %d", len(got))
			}
			if !newOperandSet([]any{pair[0]}).contains(pair[1]) {
				t.Errorf("expected a set holding one to contain the other")
			}
		})
	}
}

func unkeyedOperandsOf(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = []any{math.Inf(1), i}
	}
	return out
}

func TestPolicyOperands_UnkeyedOperandsScaleLinearly(t *testing.T) {
	t.Run("deduplication", func(t *testing.T) {
		assertScalesLinearly(t, func(t *testing.T, n int) time.Duration {
			values := unkeyedOperandsOf(n)
			started := time.Now()
			if got := DeduplicateSlice(append(values, values...)); len(got) != n {
				t.Fatalf("expected %d distinct values to survive, got %d", n, len(got))
			}
			return time.Since(started)
		})
	})
	t.Run("set membership", func(t *testing.T) {
		assertScalesLinearly(t, func(t *testing.T, n int) time.Duration {
			values := unkeyedOperandsOf(n)
			started := time.Now()
			if !isSubsetOfOperands(values, values) {
				t.Fatalf("expected a set of unkeyed values to contain each of its own members")
			}
			return time.Since(started)
		})
	})
}
