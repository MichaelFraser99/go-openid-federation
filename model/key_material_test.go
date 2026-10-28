package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwk"
)

func privateMemberKey(t *testing.T, kty string) map[string]any {
	t.Helper()
	switch kty {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		return *published
	case "EC":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		published, err := jwk.PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		return *published
	}
	t.Fatalf("unsupported kty %q", kty)
	return nil
}

func rsaJWKOfBits(t *testing.T, bits int) map[string]any {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"kty": "RSA",
		"kid": "sized",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func TestPrivateJWKMembers(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		key       map[string]any
		expect    []string
	}{
		{
			name:      "a public RSA key carries none",
			reference: "RFC 7518 6.3.1",
			key:       realJWK(t, nil, true),
		},
		{
			name:      "a public EC key carries none",
			reference: "RFC 7518 6.2.1",
			key:       realJWK(t, elliptic.P256(), false),
		},
		{
			name:      "an RSA private key names every private member it carries",
			reference: "RFC 7518 6.3.2",
			key:       privateMemberKey(t, "RSA"),
			expect:    []string{"d", "p", "q", "dp", "dq", "qi"},
		},
		{
			name:      "an EC private key names its private exponent",
			reference: "RFC 7518 6.2.2",
			key:       privateMemberKey(t, "EC"),
			expect:    []string{"d"},
		},
		{
			name:      "an OKP private key names its private exponent",
			reference: "RFC 8037 2",
			key:       map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AQAB", "d": "AQAB"},
			expect:    []string{"d"},
		},
		{
			name:      "a symmetric key is private in its entirety",
			reference: "RFC 7518 6.4.1",
			key:       map[string]any{"kty": "oct", "k": "AQAB"},
			expect:    []string{"k"},
		},
		{
			name:      "an AKP private key names its private member",
			reference: "AKP",
			key:       map[string]any{"kty": "AKP", "alg": "ML-DSA-44", "pub": "AQAB", "priv": "AQAB", "kid": "pq"},
			expect:    []string{"priv"},
		},
		{
			name:      "an AKP public key carries none",
			reference: "AKP",
			key:       map[string]any{"kty": "AKP", "alg": "ML-DSA-44", "pub": "AQAB", "kid": "pq"},
		},
		{
			name:      "other primes info is private",
			reference: "RFC 7518 6.3.2.7",
			key:       map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "oth": []any{}},
			expect:    []string{"oth"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			members := PrivateJWKMembers(tc.key)
			for _, want := range tc.expect {
				if !slices.Contains(members, want) {
					t.Errorf("[%s] expected %q among the private members found, got %v", tc.reference, want, members)
				}
			}
			if len(tc.expect) == 0 && len(members) != 0 {
				t.Errorf("[%s] expected a public key to carry no private members, got %v", tc.reference, members)
			}
			err := VerifyPublishableJWK(tc.key)
			if len(tc.expect) == 0 {
				if err != nil {
					t.Errorf("[%s] expected a public key to be publishable, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected a key carrying %v to be refused for publication", tc.reference, tc.expect)
			}
			for _, want := range tc.expect {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("[%s] expected the refusal to name %q, got %v", tc.reference, want, err)
				}
			}
		})
	}
}

func TestVerifyKeyStrength(t *testing.T) {
	weak := rsaJWKOfBits(t, 1024)
	strong := rsaJWKOfBits(t, 2048)

	tests := []struct {
		name      string
		reference string
		key       map[string]any
		alg       string
		expectErr string
	}{
		{name: "a 2048 bit modulus with RS256", reference: "RFC 7518 3.3", key: strong, alg: "RS256"},
		{name: "a 2048 bit modulus carrying leading zero octets", reference: "RFC 7518 6.3.1.1", key: paddedModulus(t, strong, 3), alg: "RS256"},
		{name: "a modulus one bit below the minimum", reference: "RFC 7518 3.3", key: rsaJWKOfExactBits(t, 2047), alg: "RS256", expectErr: "2047 bit RSA modulus"},
		{name: "a modulus exactly at the minimum", reference: "RFC 7518 3.3", key: rsaJWKOfExactBits(t, 2048), alg: "RS256"},
		{name: "a modulus exactly at the maximum", reference: "#214", key: rsaJWKOfExactBits(t, 8192), alg: "RS256"},
		{name: "a modulus at the maximum carrying leading zero octets", reference: "#214", key: paddedModulus(t, rsaJWKOfExactBits(t, 8192), 64), alg: "PS256"},
		{name: "a modulus one bit above the maximum", reference: "#214", key: rsaJWKOfExactBits(t, 8193), alg: "RS256", expectErr: "8193 bit RSA modulus, more than the 8192 bits"},
		{name: "a one megabit modulus with RS512", reference: "#214", key: rsaJWKOfExactBits(t, 1<<20), alg: "RS512", expectErr: "1048576 bit RSA modulus, more than the 8192 bits"},
		{name: "a one megabit modulus with PS512", reference: "#214", key: rsaJWKOfExactBits(t, 1<<20), alg: "PS512", expectErr: "1048576 bit RSA modulus, more than the 8192 bits"},
		{name: "a one megabit modulus with an algorithm that cannot use it", reference: "#214", key: rsaJWKOfExactBits(t, 1<<20), alg: "ES256"},
		{name: "an empty modulus is left to the shape check", reference: "RFC 7517 5", key: map[string]any{"kty": "RSA", "n": "", "e": "AQAB"}, alg: "RS256"},
		{name: "a 1024 bit modulus with RS256", reference: "RFC 7518 3.3", key: weak, alg: "RS256", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with RS384", reference: "RFC 7518 3.3", key: weak, alg: "RS384", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with RS512", reference: "RFC 7518 3.3", key: weak, alg: "RS512", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with PS256", reference: "RFC 7518 3.5", key: weak, alg: "PS256", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with PS384", reference: "RFC 7518 3.5", key: weak, alg: "PS384", expectErr: "1024 bit RSA modulus"},
		{name: "a 1024 bit modulus with PS512", reference: "RFC 7518 3.5", key: weak, alg: "PS512", expectErr: "1024 bit RSA modulus"},
		{name: "a weak modulus used with an algorithm the rule does not cover", reference: "RFC 7518 3.3", key: weak, alg: "RSA-OAEP"},
		{name: "an EC key has no modulus rule", reference: "RFC 7518 3.4", key: realJWK(t, elliptic.P256(), false), alg: "ES256"},
		{name: "an RSA key with no modulus is left to the shape check", reference: "RFC 7517 5", key: map[string]any{"kty": "RSA", "e": "AQAB"}, alg: "RS256"},
		{name: "an RSA key with a modulus that is not base64url is left to the shape check", reference: "RFC 7517 5", key: map[string]any{"kty": "RSA", "n": "!!!", "e": "AQAB"}, alg: "RS256"},
		{name: "a key of an unsupported type is not refused", reference: "RFC 7517 5", key: map[string]any{"kty": "Kyber768", "pk": "AQAB"}, alg: "RS256"},
		{name: "a key with no kty is not refused", reference: "RFC 7517 5", key: map[string]any{"n": "AQAB"}, alg: "RS256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyKeyStrength(tc.key, tc.alg)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key to be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected the key to be refused", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func paddedModulus(t *testing.T, key map[string]any, zeros int) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(key["n"].(string))
	if err != nil {
		t.Fatal(err)
	}
	padded := map[string]any{}
	for member, value := range key {
		padded[member] = value
	}
	padded["n"] = base64.RawURLEncoding.EncodeToString(append(make([]byte, zeros), raw...))
	return padded
}

func rsaJWKOfExactBits(t *testing.T, bits int) map[string]any {
	t.Helper()
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	modulus.Add(modulus, big.NewInt(1))
	if modulus.BitLen() != bits {
		t.Fatalf("expected a %d bit modulus, built %d bits", bits, modulus.BitLen())
	}
	return map[string]any{
		"kty": "RSA",
		"kid": "sized",
		"n":   base64.RawURLEncoding.EncodeToString(modulus.Bytes()),
		"e":   "AQAB",
	}
}

func TestVerifyPublishableStatementKeys(t *testing.T) {
	leaked := map[string]any{"kid": "leak", "kty": "oct", "k": "AQAB"}
	public := map[string]any{"kid": "good", "kty": "RSA", "n": "AQAB", "e": "AQAB"}

	tests := []struct {
		name      string
		reference string
		statement map[string]any
		expectErr string
	}{
		{
			name:      "a statement carrying only public keys",
			reference: "RFC 7518 6.3.1",
			statement: map[string]any{"jwks": map[string]any{"keys": []any{public}}},
		},
		{
			name:      "the jwks claim",
			reference: "3.1.1",
			statement: map[string]any{"jwks": map[string]any{"keys": []any{leaked}}},
			expectErr: "jwks",
		},
		{
			name:      "a metadata jwks parameter",
			reference: "5.2.1",
			statement: map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{"jwks": map[string]any{"keys": []any{leaked}}}}},
			expectErr: "metadata.openid_relying_party.jwks",
		},
		{
			name:      "a trust_mark_owners entry",
			reference: "3.1.1",
			statement: map[string]any{"trust_mark_owners": map[string]any{"https://tm.example.com/a": map[string]any{"jwks": map[string]any{"keys": []any{leaked}}}}},
			expectErr: "trust_mark_owners",
		},
		{
			name:      "a metadata policy value operand",
			reference: "6.1.2",
			statement: map[string]any{"metadata_policy": map[string]any{"openid_relying_party": map[string]any{"jwks": map[string]any{"value": map[string]any{"keys": []any{leaked}}}}}},
			expectErr: "metadata_policy.openid_relying_party.jwks",
		},
		{
			name:      "a leaked key after an entry that is not an object",
			reference: "RFC 7517 5",
			statement: map[string]any{"jwks": map[string]any{"keys": []any{"junk", leaked}}},
			expectErr: "jwks",
		},
		{
			name:      "a leaked key in one entity type among several",
			reference: "5.2.1",
			statement: map[string]any{"metadata": map[string]any{
				"federation_entity":    map[string]any{"organization_name": "x"},
				"oauth_client":         map[string]any{"client_name": "x"},
				"openid_relying_party": map[string]any{"jwks": map[string]any{"keys": []any{leaked}}},
			}},
			expectErr: "metadata.openid_relying_party.jwks",
		},
		{
			name:      "a statement with no key sets at all",
			reference: "3.1.1",
			statement: map[string]any{"iss": "https://ta.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for range 32 {
				err := VerifyPublishableStatementKeys(tc.statement)
				if tc.expectErr == "" {
					if err != nil {
						t.Fatalf("[%s] expected the statement to be publishable, got %v", tc.reference, err)
					}
					continue
				}
				if err == nil {
					t.Fatalf("[%s] a key set anywhere in the statement is served at the same URL, so it must be refused wherever map iteration reaches it", tc.reference)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected the refusal to name %q so an operator can find it, got %v", tc.reference, tc.expectErr, err)
				}
			}
		})
	}
}

func TestVerifyPublishableStatementKeys_RefusesAStatementTooDeepToScan(t *testing.T) {
	nest := func(depth int, leaf any) any {
		value := leaf
		for range depth {
			value = map[string]any{"wrapper": value}
		}
		return value
	}
	leaked := map[string]any{"jwks": map[string]any{"keys": []any{map[string]any{"kid": "leak", "kty": "oct", "k": "AQAB"}}}}

	tests := []struct {
		name      string
		reference string
		depth     int
		expectErr string
	}{
		{name: "a key set the statement nests shallowly", reference: "3.1.1", depth: 4, expectErr: "private key members"},
		{name: "a key set the statement nests well within the scan depth", reference: "3.1.1", depth: maxPublishableScanDepth / 2, expectErr: "private key members"},
		{name: "a key set the statement nests beyond the scan depth", reference: "3.1.1", depth: maxPublishableScanDepth + 4, expectErr: "nests deeper than"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			statement := map[string]any{"metadata": nest(tc.depth, leaked)}

			err := VerifyPublishableStatementKeys(statement)
			if err == nil {
				t.Fatalf("[%s] a scan that stops without saying so publishes the key it did not reach", tc.reference)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("[%s] expected the refusal to say %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}
