package keyops

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidateAndPermitVerify(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		keyOps    any
		absent    bool
		expectErr string
		verify    bool
	}{
		{name: "no key_ops", reference: "RFC 7517 4.3", absent: true, verify: true},
		{name: "verify", reference: "RFC 7517 4.3", keyOps: []any{"verify"}, verify: true},
		{name: "verify among others", reference: "RFC 7517 4.3", keyOps: []any{"sign", "verify"}, verify: true},
		{name: "an operation this library does not know", reference: "RFC 7517 4.3", keyOps: []any{"verify", "x-custom"}, verify: true},
		{name: "encrypt only", reference: "RFC 7517 4.3", keyOps: []any{"encrypt"}},
		{name: "empty", reference: "RFC 7517 4.3", keyOps: []any{}},
		{name: "null", reference: "RFC 7517 4.3", keyOps: nil, expectErr: "not an array"},
		{name: "a string", reference: "RFC 7517 4.3", keyOps: "verify", expectErr: "not an array"},
		{name: "an object", reference: "RFC 7517 4.3", keyOps: map[string]any{"verify": true}, expectErr: "not an array"},
		{name: "a number among the values", reference: "RFC 7517 4.3", keyOps: []any{"verify", 1}, expectErr: "not a string"},
		{name: "verify twice", reference: "RFC 7517 4.3", keyOps: []any{"verify", "verify"}, expectErr: "lists \"verify\" more than once"},
		{name: "values differing only in case are distinct", reference: "RFC 7517 4.3", keyOps: []any{"verify", "Verify"}, verify: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := map[string]any{"kty": "EC"}
			if !tc.absent {
				key["key_ops"] = tc.keyOps
			}
			err := Validate(key)
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected a refusal naming %q, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected well-formed key_ops, got %v", tc.reference, err)
			}
			if got := PermitVerify(key); got != tc.verify {
				t.Errorf("[%s] expected PermitVerify to be %v, got %v", tc.reference, tc.verify, got)
			}
		})
	}
}

func TestValidate_ADuplicateIsFoundWhereverItSits(t *testing.T) {
	ops := make([]any, 0, 10001)
	for i := range 10000 {
		ops = append(ops, "op-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+base64.RawURLEncoding.EncodeToString([]byte{byte(i >> 8), byte(i)}))
	}
	ops = append(ops, ops[0])
	if err := Validate(map[string]any{"key_ops": ops}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("[RFC 7517 4.3] expected the duplicate at the end of a long array to be found, got %v", err)
	}
}
