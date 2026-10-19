package entity_statement

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func unsignedToken(t *testing.T, head, body map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(head) + "." + encode(body) + ".signature"
}
