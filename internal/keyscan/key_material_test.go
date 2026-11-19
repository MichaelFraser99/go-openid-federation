package keyscan

import (
	"strings"
	"testing"
)

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
