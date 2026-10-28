package model

import (
	"testing"
)

func TestPublicKeyFingerprint_MatchesAKeyHoweverItIsEncoded(t *testing.T) {
	rsa := map[string]any{"kty": "RSA", "n": "AQIDBA", "e": "AQAB"}
	ec := map[string]any{"kty": "EC", "crv": "P-256", "x": "AQID", "y": "BAUG"}
	okp := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AQID"}

	tests := map[string]struct {
		a, b     map[string]any
		expected bool
	}{
		"the same RSA key":                      {a: rsa, b: map[string]any{"kty": "RSA", "n": "AQIDBA", "e": "AQAB", "kid": "other", "alg": "RS256"}, expected: true},
		"an RSA modulus with a leading zero":    {a: rsa, b: map[string]any{"kty": "RSA", "n": "AAECAwQ", "e": "AQAB"}, expected: true},
		"an RSA exponent with a leading zero":   {a: rsa, b: map[string]any{"kty": "RSA", "n": "AQIDBA", "e": "AAEAAQ"}, expected: true},
		"a different RSA modulus":               {a: rsa, b: map[string]any{"kty": "RSA", "n": "AQIDBQ", "e": "AQAB"}},
		"a different RSA exponent":              {a: rsa, b: map[string]any{"kty": "RSA", "n": "AQIDBA", "e": "Aw"}},
		"the same EC key":                       {a: ec, b: map[string]any{"kty": "EC", "crv": "P-256", "x": "AQID", "y": "BAUG", "kid": "x"}, expected: true},
		"an EC coordinate with a leading zero":  {a: ec, b: map[string]any{"kty": "EC", "crv": "P-256", "x": "AAECAw", "y": "BAUG"}, expected: true},
		"the same EC point on another curve":    {a: ec, b: map[string]any{"kty": "EC", "crv": "P-384", "x": "AQID", "y": "BAUG"}},
		"swapped EC coordinates":                {a: ec, b: map[string]any{"kty": "EC", "crv": "P-256", "x": "BAUG", "y": "AQID"}},
		"the same EC x with another y":          {a: ec, b: map[string]any{"kty": "EC", "crv": "P-256", "x": "AQID", "y": "BwgJ"}},
		"the same OKP key":                      {a: okp, b: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AQID"}, expected: true},
		"an OKP key on another curve":           {a: okp, b: map[string]any{"kty": "OKP", "crv": "X25519", "x": "AQID"}},
		"an OKP key whose leading zero matters": {a: okp, b: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AAECAw"}},
		"an RSA and an EC key over equal bytes": {a: map[string]any{"kty": "RSA", "n": "AQID", "e": "BAUG"}, b: ec},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := SharesAPublicKey([]map[string]any{tc.a}, []map[string]any{tc.b}); got != tc.expected {
				t.Errorf("expected a match %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestPublicKeyFingerprint_RefusesWhatItCannotRead(t *testing.T) {
	tests := map[string]map[string]any{
		"an unknown key type":           {"kty": "AKP", "pub": "AQID"},
		"a symmetric key":               {"kty": "oct", "k": "AQID"},
		"no key type":                   {"n": "AQID", "e": "AQAB"},
		"an RSA key with no modulus":    {"kty": "RSA", "e": "AQAB"},
		"an RSA key with no exponent":   {"kty": "RSA", "n": "AQID"},
		"a modulus that is not text":    {"kty": "RSA", "n": 5, "e": "AQAB"},
		"a modulus that is not b64":     {"kty": "RSA", "n": "!!", "e": "AQAB"},
		"an empty modulus":              {"kty": "RSA", "n": "", "e": "AQAB"},
		"an EC key with no curve":       {"kty": "EC", "x": "AQID", "y": "BAUG"},
		"an EC key with an empty curve": {"kty": "EC", "crv": "", "x": "AQID", "y": "BAUG"},
		"an EC key with no y":           {"kty": "EC", "crv": "P-256", "x": "AQID"},
		"an OKP key with no curve":      {"kty": "OKP", "x": "AQID"},
		"an OKP key with no x":          {"kty": "OKP", "crv": "Ed25519"},
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := PublicKeyFingerprint(key); ok {
				t.Errorf("expected no fingerprint for a key that cannot be read")
			}
			if SharesAPublicKey([]map[string]any{key}, []map[string]any{key}) {
				t.Errorf("expected a key with no fingerprint to match nothing, not even itself")
			}
		})
	}
}
