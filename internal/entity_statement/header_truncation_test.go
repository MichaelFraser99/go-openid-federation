package entity_statement

import (
	"strings"
	"testing"
)

func TestValidateStatementHeader_BoundsTheQuotedTyp(t *testing.T) {
	tests := []struct {
		name      string
		typ       string
		truncated bool
	}{
		{name: "a short typ is quoted in full", typ: "JWT"},
		{name: "a long typ is bounded", typ: strings.Repeat("A", 1<<16), truncated: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStatementHeader(map[string]any{"typ": tc.typ, "alg": "RS256"})
			if err == nil {
				t.Fatal("expected a non-conforming typ to be refused")
			}
			if len(err.Error()) > maxQuotedHeaderBytes+256 {
				t.Fatalf("expected the error to be bounded, got %d bytes", len(err.Error()))
			}
			if tc.truncated && !strings.Contains(err.Error(), "...") {
				t.Error("expected a bounded typ to be marked as truncated")
			}
			if !tc.truncated && !strings.Contains(err.Error(), tc.typ) {
				t.Errorf("expected a short typ to be quoted in full, got %v", err)
			}
		})
	}
}
