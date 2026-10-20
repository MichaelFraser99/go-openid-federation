package model

import (
	"encoding/json"
	"fmt"
	"testing"
)

func benchmarkConflictWalk(b *testing.B, n int) {
	b.Helper()
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf("%q", fmt.Sprintf("value-%d", i))
	}
	list := "[" + join(values) + "]"
	raw := fmt.Sprintf(`{"openid_relying_party":{"contacts":{"value":%s,"add":%s,"subset_of":%s,"superset_of":%s}}}`, list, list, list, list)

	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		b.Fatalf("failed to parse the policy fixture: %v", err)
	}
	subordinate := EntityStatement{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &policy}
	chain := []EntityStatement{subordinate}

	b.ResetTimer()
	for range b.N {
		if _, err := ProcessAndExtractPolicy(chain); err != nil {
			b.Fatalf("unexpected policy error: %v", err)
		}
	}
}

func join(values []string) string {
	out := ""
	for i, v := range values {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func BenchmarkPolicyConflictWalk5(b *testing.B)   { benchmarkConflictWalk(b, 5) }
func BenchmarkPolicyConflictWalk100(b *testing.B) { benchmarkConflictWalk(b, 100) }
func BenchmarkPolicyConflictWalk500(b *testing.B) { benchmarkConflictWalk(b, 500) }
