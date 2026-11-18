package model

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func leakedKey(kid string, member string) map[string]any {
	key := map[string]any{member: "SECRETVALUE"}
	if kid != "" {
		key["kid"] = kid
	}
	return key
}

func publicKey(kid string) map[string]any {
	return map[string]any{"kid": kid, "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
}

func TestVerifyPublishableStatementKeys_FindsAPrivateKeyAnywhereInsideAJwksValue(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		statement func() map[string]any
		expectErr string
	}{
		{
			name:      "a custom entity type whose jwks is a bare private JWK",
			reference: "RFC 7518 6.2.2",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": leakedKey("bare", "d")}}}
			},
			expectErr: "metadata.x_custom.jwks",
		},
		{
			name:      "a custom entity type whose jwks is an array holding a private AKP key",
			reference: "RFC 9964",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": []any{publicKey("good"), leakedKey("array", "priv")}}}}
			},
			expectErr: "metadata.x_custom.jwks",
		},
		{
			name:      "a jwks whose keys member is an object holding a private symmetric key",
			reference: "RFC 7518 6.4",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": map[string]any{"keys": map[string]any{"0": leakedKey("object", "k")}}}}}
			},
			expectErr: "metadata.x_custom.jwks.0",
		},
		{
			name:      "a private key held inside a member of a public key",
			reference: "RFC 7518 6.3.2",
			statement: func() map[string]any {
				outer := publicKey("outer")
				outer["x_inner"] = leakedKey("inner", "p")
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": map[string]any{"keys": []any{outer}}}}}
			},
			expectErr: "metadata.x_custom.jwks.x_inner",
		},
		{
			name:      "a bare private JWK with no kid and no kty in the jwks claim",
			reference: "RFC 7517 4.5",
			statement: func() map[string]any {
				return map[string]any{"jwks": leakedKey("", "qi")}
			},
			expectErr: "jwks",
		},
		{
			name:      "a policy value operand that is a bare private JWK",
			reference: "6.1.3.1.1",
			statement: func() map[string]any {
				return map[string]any{"metadata_policy": map[string]any{"x_custom": map[string]any{"jwks": map[string]any{"value": leakedKey("operand", "dp")}}}}
			},
			expectErr: "metadata_policy.x_custom.jwks.value",
		},
		{
			name:      "a trust_mark_owners entry whose jwks is an array of arrays",
			reference: "3.1.1",
			statement: func() map[string]any {
				return map[string]any{"trust_mark_owners": map[string]any{"https://tm.example.com/a": map[string]any{"jwks": []any{[]any{leakedKey("nested", "oth")}}}}}
			},
			expectErr: "trust_mark_owners.https://tm.example.com/a.jwks",
		},
		{
			name:      "a custom entity type whose jwks is a bare public JWK",
			reference: "RFC 7517 4",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": publicKey("bare")}}}
			},
		},
		{
			name:      "a custom entity type whose jwks is an array of public JWKs",
			reference: "RFC 7517 4",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": []any{publicKey("a"), publicKey("b")}}}}
			},
		},
		{
			name:      "a private key under a member named JWKS, which the scan does not treat as a key set",
			reference: "PUB-8",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"JWKS": leakedKey("upper", "d")}}}
			},
		},
		{
			name:      "a private key under a member named jwk, which the scan does not treat as a key set",
			reference: "PUB-8",
			statement: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwk": leakedKey("single", "d")}}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for range 32 {
				err := VerifyPublishableStatementKeys(tc.statement())
				if tc.expectErr == "" {
					if err != nil {
						t.Fatalf("[%s] expected the statement to be publishable, got %v", tc.reference, err)
					}
					continue
				}
				if err == nil {
					t.Fatalf("[%s] a private key anywhere inside a jwks value is published with the statement, so it must be refused", tc.reference)
				}
				if !strings.Contains(err.Error(), "private key members") || !strings.Contains(err.Error(), strconv.Quote(tc.expectErr)+" key set") {
					t.Fatalf("[%s] expected the refusal to name the private members and the path %q, got %v", tc.reference, tc.expectErr, err)
				}
				if strings.Contains(err.Error(), "SECRETVALUE") {
					t.Fatalf("[%s] the refusal carries the private value: %v", tc.reference, err)
				}
			}
		})
	}
}

func TestStripUnpublishableKeys_RemovesEveryPrivateKeyInsideAJwksValue(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		entity    func() map[string]any
		expect    map[string]any
		dropped   []string
	}{
		{
			name:      "a jwks claim that is a bare private JWK",
			reference: "RFC 7518 6.2.2",
			entity: func() map[string]any {
				return map[string]any{"id": "https://rp.example.com", "jwks": leakedKey("bare", "d")}
			},
			expect:  map[string]any{"id": "https://rp.example.com"},
			dropped: []string{"bare"},
		},
		{
			name:      "a custom entity type whose jwks is a bare private JWK",
			reference: "RFC 7518 6.2.2",
			entity: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"jwks": leakedKey("bare", "d"), "name": "rp"}}}
			},
			expect:  map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"name": "rp"}}},
			dropped: []string{"bare"},
		},
		{
			name:      "a jwks that is an array holding a public and a private key",
			reference: "RFC 9964",
			entity: func() map[string]any {
				return map[string]any{"jwks": []any{publicKey("good"), leakedKey("array", "priv")}}
			},
			expect:  map[string]any{"jwks": []any{publicKey("good")}},
			dropped: []string{"array"},
		},
		{
			name:      "a jwks whose keys member is an object",
			reference: "RFC 7518 6.4",
			entity: func() map[string]any {
				return map[string]any{"jwks": map[string]any{"keys": map[string]any{"0": leakedKey("object", "k"), "1": publicKey("good")}}}
			},
			expect:  map[string]any{"jwks": map[string]any{"keys": map[string]any{"1": publicKey("good")}}},
			dropped: []string{"object"},
		},
		{
			name:      "a jwks keys array holding a public and a private key",
			reference: "RFC 7518 6.3.2",
			entity: func() map[string]any {
				return map[string]any{"jwks": map[string]any{"keys": []any{publicKey("good"), leakedKey("leaked", "q")}}}
			},
			expect:  map[string]any{"jwks": map[string]any{"keys": []any{publicKey("good")}}},
			dropped: []string{"leaked"},
		},
		{
			name:      "a private key held inside a member of a public key",
			reference: "RFC 7518 6.3.2",
			entity: func() map[string]any {
				outer := publicKey("outer")
				outer["x_inner"] = leakedKey("inner", "dq")
				return map[string]any{"jwks": map[string]any{"keys": []any{outer}}}
			},
			expect:  map[string]any{"jwks": map[string]any{"keys": []any{publicKey("outer")}}},
			dropped: []string{"inner"},
		},
		{
			name:      "a jwks member inside an array of arrays",
			reference: "RFC 7518 6.2.2",
			entity: func() map[string]any {
				return map[string]any{"x_rows": []any{[]any{map[string]any{"jwks": map[string]any{"keys": []any{leakedKey("deep", "d")}}}}}}
			},
			expect:  map[string]any{"x_rows": []any{[]any{map[string]any{"jwks": map[string]any{"keys": []any{}}}}}},
			dropped: []string{"deep"},
		},
		{
			name:      "a jwks that is an array of arrays",
			reference: "RFC 7518 6.2.2",
			entity: func() map[string]any {
				return map[string]any{"jwks": []any{[]any{leakedKey("nested", "oth"), publicKey("good")}}}
			},
			expect:  map[string]any{"jwks": []any{[]any{publicKey("good")}}},
			dropped: []string{"nested"},
		},
		{
			name:      "a jwks that is a bare public JWK",
			reference: "RFC 7517 4",
			entity: func() map[string]any {
				return map[string]any{"jwks": publicKey("bare")}
			},
			expect: map[string]any{"jwks": publicKey("bare")},
		},
		{
			name:      "a private key under a member named JWKS, which the scan does not treat as a key set",
			reference: "PUB-8",
			entity: func() map[string]any {
				return map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"JWKS": leakedKey("upper", "d")}}}
			},
			expect: map[string]any{"metadata": map[string]any{"x_custom": map[string]any{"JWKS": leakedKey("upper", "d")}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entity := tc.entity()
			var dropped []string
			StripUnpublishableKeys(entity, 0, &dropped)

			if !reflect.DeepEqual(entity, tc.expect) {
				t.Errorf("[%s] expected every object carrying private members removed from inside the jwks value and nothing else, got %v", tc.reference, entity)
			}
			slices.Sort(dropped)
			if !slices.Equal(dropped, tc.dropped) {
				t.Errorf("[%s] expected the dropped key IDs %v, got %v", tc.reference, tc.dropped, dropped)
			}
		})
	}
}
