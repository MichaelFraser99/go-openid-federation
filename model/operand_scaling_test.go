package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	scalingBaseCount = 40000
	scalingFactor    = 4
	scalingTolerance = 9
	scalingBudget    = 3 * time.Second
)

func operandStrings(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("value-%d", i)
	}
	return out
}

func operandJSON(n int) string {
	vals := make([]string, n)
	for i := range vals {
		vals[i] = fmt.Sprintf("%q", fmt.Sprintf("value-%d", i))
	}
	return "[" + strings.Join(vals, ",") + "]"
}

func assertScalesLinearly(t *testing.T, measure func(*testing.T, int) time.Duration) {
	t.Helper()

	small := measure(t, scalingBaseCount)
	if small > scalingBudget {
		t.Fatalf("%d operands took %s, which is beyond any linear cost", scalingBaseCount, small)
	}

	large := measure(t, scalingBaseCount*scalingFactor)
	if large > time.Duration(scalingTolerance)*small {
		t.Fatalf("%d operands took %s and %d took %s, a factor of %.1f for %dx the work, which is the quadratic cost returning",
			scalingBaseCount, small, scalingBaseCount*scalingFactor, large, float64(large)/float64(small), scalingFactor)
	}
	t.Logf("%s at %d, %s at %d, a factor of %.1f", small, scalingBaseCount, large, scalingBaseCount*scalingFactor, float64(large)/float64(small))
}

func TestPolicyOperands_ResolveScalesLinearly(t *testing.T) {
	tests := []struct {
		name     string
		operator string
	}{
		{name: "subset_of", operator: "subset_of"},
		{name: "superset_of", operator: "superset_of"},
		{name: "one_of", operator: "one_of"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertScalesLinearly(t, func(t *testing.T, count int) time.Duration {
				t.Helper()
				var parsed PolicyOperators
				if err := json.Unmarshal([]byte(`{"`+test.operator+`":`+operandJSON(count)+`}`), &parsed); err != nil {
					t.Fatalf("the fixture did not parse: %v", err)
				}

				metadata := any(operandStrings(count))
				if test.operator == "one_of" {
					metadata = fmt.Sprintf("value-%d", count-1)
				}

				started := time.Now()
				if _, err := parsed.Metadata[0].Resolve(metadata); err != nil {
					t.Fatalf("expected the operator to resolve, got %v", err)
				}
				return time.Since(started)
			})
		})
	}
}

func TestPolicyOperands_MergeScalesLinearly(t *testing.T) {
	tests := []struct {
		name  string
		first string
		other string
	}{
		{name: "two subset_of levels", first: "subset_of", other: "subset_of"},
		{name: "subset_of over add", first: "subset_of", other: "add"},
		{name: "two one_of levels", first: "one_of", other: "one_of"},
		{name: "two superset_of levels", first: "superset_of", other: "superset_of"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertScalesLinearly(t, func(t *testing.T, count int) time.Duration {
				t.Helper()
				var a, b PolicyOperators
				if err := json.Unmarshal([]byte(`{"`+test.first+`":`+operandJSON(count)+`}`), &a); err != nil {
					t.Fatalf("the first fixture did not parse: %v", err)
				}
				if err := json.Unmarshal([]byte(`{"`+test.other+`":`+operandJSON(count)+`}`), &b); err != nil {
					t.Fatalf("the second fixture did not parse: %v", err)
				}

				started := time.Now()
				if _, err := MergePolicyOperators("contacts", a, b); err != nil {
					t.Fatalf("expected the two levels to merge, got %v", err)
				}
				return time.Since(started)
			})
		})
	}
}

func TestPolicyOperands_ConflictDetectionScalesLinearly(t *testing.T) {
	tests := []struct {
		name  string
		first string
		other string
	}{
		{name: "subset_of against superset_of", first: "subset_of", other: "superset_of"},
		{name: "value against add", first: "value", other: "add"},
		{name: "value against subset_of", first: "value", other: "subset_of"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertScalesLinearly(t, func(t *testing.T, count int) time.Duration {
				t.Helper()
				operands := operandJSON(count)
				raw := `{"openid_relying_party":{"contacts":{"` + test.first + `":` + operands + `,"` + test.other + `":` + operands + `}}}`

				var policy MetadataPolicy
				if err := json.Unmarshal([]byte(raw), &policy); err != nil {
					t.Fatalf("the fixture did not parse: %v", err)
				}

				started := time.Now()
				if err := sortAndValidatePolicy(&policy); err != nil {
					t.Fatalf("expected the policy to validate, got %v", err)
				}
				return time.Since(started)
			})
		})
	}
}

func benchmarkSubsetResolve(b *testing.B, n int) {
	b.Helper()
	var parsed PolicyOperators
	if err := json.Unmarshal([]byte(`{"subset_of":`+operandJSON(n)+`}`), &parsed); err != nil {
		b.Fatal(err)
	}
	metadata := operandStrings(n)

	b.ResetTimer()
	for range b.N {
		if _, err := parsed.Metadata[0].Resolve(metadata); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSubsetOfResolve1000(b *testing.B)  { benchmarkSubsetResolve(b, 1000) }
func BenchmarkSubsetOfResolve10000(b *testing.B) { benchmarkSubsetResolve(b, 10000) }
