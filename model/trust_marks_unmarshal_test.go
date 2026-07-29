package model

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// An Entity Configuration that carries trust_marks (per OpenID Federation 1.0 section 3.2) must retain
// them after unmarshalling, so downstream consumers (resolve, ResolveMetadata) can surface them.
func TestEntityStatement_UnmarshalJSON_KeepsTrustMarks(t *testing.T) {
	now := time.Now()
	raw := fmt.Sprintf(`{
		"iss": "https://trust.example.com",
		"sub": "https://provider.example.com/wallet",
		"iat": %d,
		"exp": %d,
		"jwks": {"keys": []},
		"trust_marks": [
			{"trust_mark_type": "https://trust.example.com/tm/product", "trust_mark": "eyJhbGciOiJFUzI1NiJ9.e30.sig"}
		]
	}`, now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix())

	var es EntityStatement
	if err := json.Unmarshal([]byte(raw), &es); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := len(es.TrustMarks); got != 1 {
		t.Fatalf("expected 1 trust mark, got %d", got)
	}
	if es.TrustMarks[0].TrustMarkType != "https://trust.example.com/tm/product" {
		t.Fatalf("trust_mark_type: got %q", es.TrustMarks[0].TrustMarkType)
	}
	if es.TrustMarks[0].TrustMark != "eyJhbGciOiJFUzI1NiJ9.e30.sig" {
		t.Fatalf("trust_mark: got %q", es.TrustMarks[0].TrustMark)
	}
}
