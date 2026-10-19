package entity_configuration

import (
	"encoding/json"
	"testing"
)

func marshalClaims(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}
	return raw
}
