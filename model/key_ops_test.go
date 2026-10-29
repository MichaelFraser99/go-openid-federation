package model

import (
	"encoding/base64"
	"strings"
	"testing"
)

func modulusOfBits(bits int) string {
	raw := make([]byte, (bits+7)/8)
	for i := range raw {
		raw[i] = 0xff
	}
	if spare := len(raw)*8 - bits; spare > 0 {
		raw[0] >>= spare
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestVerifyKeyStrengthForAnyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expectErr string
	}{
		{name: "a 2048 bit RSA key", reference: "RFC 7518 3.3", key: map[string]any{"kty": "RSA", "n": modulusOfBits(2048), "e": "AQAB"}},
		{name: "a 2047 bit RSA key", reference: "RFC 7518 3.3", key: map[string]any{"kty": "RSA", "n": modulusOfBits(2047), "e": "AQAB"}, expectErr: "2047 bit RSA modulus"},
		{name: "a 2048 bit RSA key written with a leading zero octet", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(append([]byte{0}, func() []byte { raw, _ := base64.RawURLEncoding.DecodeString(modulusOfBits(2048)); return raw }()...)), "e": "AQAB"}},
		{name: "an RSA key above this library's maximum", reference: "RFC 7517 4.4", key: map[string]any{"kty": "RSA", "n": modulusOfBits(16384), "e": "AQAB"}},
		{name: "an EC key", reference: "RFC 7518 6.2", key: map[string]any{"kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}},
		{name: "an RSA key with no modulus is left to the shape check", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kty": "RSA", "e": "AQAB"}},
		{name: "an RSA key whose modulus is not base64url is left to the parser", reference: "RFC 7518 6.3.1.1", key: map[string]any{"kty": "RSA", "n": "not base64!", "e": "AQAB"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyKeyStrengthForAnyAlgorithm(tc.key)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key to pass, got %v", tc.reference, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected a refusal naming %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestValidateKeyOpsAndKeyOpsPermitVerify(t *testing.T) {
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
			err := ValidateKeyOps(key)
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected a refusal naming %q, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected well-formed key_ops, got %v", tc.reference, err)
			}
			if got := KeyOpsPermitVerify(key); got != tc.verify {
				t.Errorf("[%s] expected KeyOpsPermitVerify to be %v, got %v", tc.reference, tc.verify, got)
			}
		})
	}
}

func TestValidateKeyOps_ADuplicateIsFoundWhereverItSits(t *testing.T) {
	ops := make([]any, 0, 10001)
	for i := range 10000 {
		ops = append(ops, "op-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+base64.RawURLEncoding.EncodeToString([]byte{byte(i >> 8), byte(i)}))
	}
	ops = append(ops, ops[0])
	if err := ValidateKeyOps(map[string]any{"key_ops": ops}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("[RFC 7517 4.3] expected the duplicate at the end of a long array to be found, got %v", err)
	}
}
