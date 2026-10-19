package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
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

func TestPolicyOperands_ScaleLinearly(t *testing.T) {
	// Each of these was quadratic in the operand count, and a peer supplies the
	// operands inside a subordinate statement. The budget is generous: at the
	// previous cost the 60,000 cases took tens of seconds.
	const budget = 5 * time.Second

	tests := []struct {
		name     string
		operator string
		count    int
	}{
		{name: "subset_of resolve", operator: "subset_of", count: 60000},
		{name: "superset_of resolve", operator: "superset_of", count: 60000},
		{name: "one_of resolve", operator: "one_of", count: 60000},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var parsed PolicyOperators
			if err := json.Unmarshal([]byte(`{"`+tc.operator+`":`+operandJSON(tc.count)+`}`), &parsed); err != nil {
				t.Fatalf("the fixture did not parse: %v", err)
			}

			metadata := any(operandStrings(tc.count))
			if tc.operator == "one_of" {
				metadata = "value-7"
			}

			started := time.Now()
			if _, err := parsed.Metadata[0].Resolve(metadata); err != nil {
				t.Fatalf("expected the operator to resolve, got %v", err)
			}
			if elapsed := time.Since(started); elapsed > budget {
				t.Fatalf("resolving %d operands took %s, which is the quadratic cost returning", tc.count, elapsed)
			}
		})
	}
}

func TestPolicyOperands_MergeScalesLinearly(t *testing.T) {
	const budget = 5 * time.Second
	const count = 40000

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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var a, b PolicyOperators
			if err := json.Unmarshal([]byte(`{"`+tc.first+`":`+operandJSON(count)+`}`), &a); err != nil {
				t.Fatalf("the first fixture did not parse: %v", err)
			}
			if err := json.Unmarshal([]byte(`{"`+tc.other+`":`+operandJSON(count)+`}`), &b); err != nil {
				t.Fatalf("the second fixture did not parse: %v", err)
			}

			started := time.Now()
			if _, err := MergePolicyOperators("contacts", a, b); err != nil {
				t.Fatalf("expected the two levels to merge, got %v", err)
			}
			if elapsed := time.Since(started); elapsed > budget {
				t.Fatalf("merging %d operands took %s, which is the quadratic cost returning", count, elapsed)
			}
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

func TestPolicyOperands_ConflictDetectionScalesLinearly(t *testing.T) {
	// validatePoliciesCanCombine compares each operand of one operator against
	// each operand of another, on every statement's own policy, so this is
	// reachable from a single subordinate statement.
	const budget = 5 * time.Second
	const count = 40000

	tests := []struct {
		name   string
		policy string
	}{
		{
			name:   "subset_of against superset_of",
			policy: `{"openid_relying_party":{"contacts":{"subset_of":` + operandJSON(count) + `,"superset_of":` + operandJSON(count) + `}}}`,
		},
		{
			name:   "value against add",
			policy: `{"openid_relying_party":{"contacts":{"value":` + operandJSON(count) + `,"add":` + operandJSON(count) + `}}}`,
		},
		{
			name:   "value against subset_of",
			policy: `{"openid_relying_party":{"contacts":{"value":` + operandJSON(count) + `,"subset_of":` + operandJSON(count) + `}}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("the policy fixture did not parse: %v", err)
			}
			subordinate := EntityStatement{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &policy}

			started := time.Now()
			if _, err := ProcessAndExtractPolicy([]EntityStatement{{}, subordinate, {}}); err != nil {
				t.Fatalf("expected the policy to validate, got %v", err)
			}
			if elapsed := time.Since(started); elapsed > budget {
				t.Fatalf("validating %d operands took %s, which is the quadratic cost returning", count, elapsed)
			}
		})
	}
}
