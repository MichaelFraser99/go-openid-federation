package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func base64RawURL(body string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(body))
}

func TestParseJWKSet(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		value     any
		keys      int
		expectErr string
	}{
		{
			name:      "a key set with one well formed key",
			reference: "RFC 7517 5.1",
			value:     map[string]any{"keys": []any{map[string]any{"kid": "a", "kty": "RSA", "n": "AQAB", "e": "AQAB"}}},
			keys:      1,
		},
		{
			name:      "an empty keys array",
			reference: "RFC 7517 5.1",
			value:     map[string]any{"keys": []any{}},
			keys:      0,
		},
		{
			name:      "a member that case folds to keys does not supply the keys",
			reference: "RFC 7517 6",
			value:     map[string]any{"keyſ": []any{map[string]any{"kid": "a", "kty": "RSA"}}},
			expectErr: "is missing the required 'keys' member",
		},
		{
			name:      "an upper case keys member does not supply the keys",
			reference: "RFC 7517 6",
			value:     map[string]any{"KEYS": []any{map[string]any{"kid": "a", "kty": "RSA"}}},
			expectErr: "is missing the required 'keys' member",
		},
		{
			name:      "a key missing the required kty is ignored",
			reference: "RFC 7517 5",
			value:     map[string]any{"keys": []any{map[string]any{"kid": "a"}}},
			keys:      0,
		},
		{
			name:      "a second key missing the required kty is ignored",
			reference: "RFC 7517 5",
			value:     map[string]any{"keys": []any{map[string]any{"kid": "a", "kty": "RSA"}, map[string]any{"kid": "b"}}},
			keys:      1,
		},
		{
			name:      "an EC key missing the required crv is ignored",
			reference: "RFC 7517 5",
			value:     map[string]any{"keys": []any{map[string]any{"kid": "a", "kty": "EC", "x": "AQAB", "y": "AQAB"}}},
			keys:      0,
		},
		{
			name:      "a key of a type this implementation may not support is kept",
			reference: "RFC 7517 4.1",
			value:     map[string]any{"keys": []any{map[string]any{"kid": "a", "kty": "AKP", "pub": "AQAB"}}},
			keys:      1,
		},
		{
			name:      "a key that is not an object",
			reference: "RFC 7517 5.1",
			value:     map[string]any{"keys": []any{"not-a-key"}},
			expectErr: "position 0 of 'keys' that is not a JSON object",
		},
		{
			name:      "a key set that is not an object",
			reference: "RFC 7517 5",
			value:     []any{},
			expectErr: "must be a JSON object",
		},
		{
			name:      "a keys member that is not an array",
			reference: "RFC 7517 5",
			value:     map[string]any{"keys": map[string]any{}},
			expectErr: "has a 'keys' member that is not an array",
		},
		{
			name:      "a null keys member",
			reference: "RFC 7517 5",
			value:     map[string]any{"keys": nil},
			expectErr: "has a 'keys' member that is not an array",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseJWKSet(tc.value)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the key set to be accepted, got %v", tc.reference, err)
				}
				if len(parsed.Keys) != tc.keys {
					t.Errorf("[%s] expected %d usable keys, got %d", tc.reference, tc.keys, len(parsed.Keys))
				}
				for i, key := range parsed.Keys {
					if err := ValidateJWKShape(key); err != nil {
						t.Errorf("[%s] key %d was kept though it %s", tc.reference, i, err.Error())
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error naming %s, got %d keys", tc.reference, tc.expectErr, len(parsed.Keys))
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestEntityStatement_AKeySetMemberThatCaseFoldsDoesNotSupplyTheKeys(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		jwks      string
		expectErr string
	}{
		{
			name:      "the exact member supplies the keys",
			reference: "3.2 step 9",
			jwks:      `{"keys":[{"kid":"real","kty":"RSA","n":"AQAB","e":"AQAB"}]}`,
		},
		{
			name:      "a folded member alongside the exact one is not read as keys",
			reference: "RFC 7517 6",
			jwks:      `{"keys":[{"kid":"real","kty":"RSA","n":"AQAB","e":"AQAB"}],"keyſ":[{"kid":"forged","kty":"RSA","n":"AQAB","e":"AQAB"}]}`,
		},
		{
			name:      "a folded member alone leaves the statement without keys",
			reference: "RFC 7517 6",
			jwks:      `{"keyſ":[{"kid":"forged","kty":"RSA","n":"AQAB","e":"AQAB"}]}`,
			expectErr: "is missing the required 'keys' member",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"iss":"https://a.example.com","sub":"https://a.example.com","iat":%d,"exp":%d,"jwks":%s}`, time.Now().Unix(), time.Now().Add(time.Hour).Unix(), tc.jwks)
			var statement EntityStatement
			err := json.Unmarshal([]byte(body), &statement)

			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("[%s] expected the statement to be refused, got keys %v", tc.reference, statement.JWKs.Keys)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the statement to be accepted, got %v", tc.reference, err)
			}
			if len(statement.JWKs.Keys) != 1 {
				t.Fatalf("[%s] expected exactly the keys of the exact member, got %d", tc.reference, len(statement.JWKs.Keys))
			}
			if statement.JWKs.Keys[0]["kid"] != "real" {
				t.Errorf("[%s] expected the key of the exact 'keys' member, got %v", tc.reference, statement.JWKs.Keys[0]["kid"])
			}
		})
	}
}

func TestTrustMarkHolder_MembersAreReadByTheirExactName(t *testing.T) {
	mark := func(trustMarkType string) string {
		return "e30." + base64RawURL(fmt.Sprintf(`{"trust_mark_type":%q}`, trustMarkType)) + ".c2ln"
	}

	tests := []struct {
		name      string
		reference string
		entry     string
		expectErr string
	}{
		{
			name:      "the exact member names",
			reference: "3.1.2",
			entry:     fmt.Sprintf(`{"trust_mark_type":"https://tm.example.com/a","trust_mark":%q}`, mark("https://tm.example.com/a")),
		},
		{
			name:      "a trust_mark_type that case folds is not read as the member",
			reference: "RFC 7517 6",
			entry:     fmt.Sprintf(`{"truſt_mark_type":"https://tm.example.com/a","trust_mark":%q}`, mark("https://tm.example.com/a")),
			expectErr: "requires a non-empty 'trust_mark_type' member",
		},
		{
			name:      "an upper case trust_mark member is not read as the member",
			reference: "RFC 7517 6",
			entry:     fmt.Sprintf(`{"trust_mark_type":"https://tm.example.com/a","TRUST_MARK":%q}`, mark("https://tm.example.com/a")),
			expectErr: "requires a non-empty 'trust_mark' member",
		},
		{
			name:      "a claim inside the mark that case folds does not satisfy the comparison",
			reference: "3.1.2",
			entry:     fmt.Sprintf(`{"trust_mark_type":"https://tm.example.com/a","trust_mark":%q}`, "e30."+base64RawURL(`{"truſt_mark_type":"https://tm.example.com/a"}`)+".c2ln"),
			expectErr: "has no 'trust_mark_type' claim",
		},
		{
			name:      "a trust_mark_type claim that is not a string",
			reference: "3.1.2",
			entry:     fmt.Sprintf(`{"trust_mark_type":"https://tm.example.com/a","trust_mark":%q}`, "e30."+base64RawURL(`{"trust_mark_type":7}`)+".c2ln"),
			expectErr: "malformed 'trust_mark_type' claim",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var holder TrustMarkHolder
			err := json.Unmarshal([]byte(tc.entry), &holder)

			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("[%s] expected the entry to be refused, got type %q", tc.reference, holder.TrustMarkType)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the entry to be accepted, got %v", tc.reference, err)
			}
			if holder.TrustMarkType != "https://tm.example.com/a" {
				t.Errorf("[%s] expected the exact member value, got %q", tc.reference, holder.TrustMarkType)
			}
		})
	}
}

func TestTrustMarkOwner_MembersAreReadByTheirExactName(t *testing.T) {
	keys := `{"keys":[{"kid":"a","kty":"RSA","n":"AQAB","e":"AQAB"}]}`

	tests := []struct {
		name      string
		reference string
		entry     string
		expectErr string
	}{
		{
			name:      "the exact member names",
			reference: "3.1.2",
			entry:     `{"sub":"https://owner.example.com","jwks":` + keys + `}`,
		},
		{
			name:      "a sub that case folds is not read as the member",
			reference: "RFC 7517 6",
			entry:     `{"ſub":"https://evil.example.com","jwks":` + keys + `}`,
			expectErr: "missing the required 'sub' member",
		},
		{
			name:      "a jwks that case folds is not read as the member",
			reference: "RFC 7517 6",
			entry:     `{"sub":"https://owner.example.com","jwkſ":` + keys + `}`,
			expectErr: "missing the required 'jwks' member",
		},
		{
			name:      "a keys member that case folds supplies no keys",
			reference: "RFC 7517 6",
			entry:     `{"sub":"https://owner.example.com","jwks":{"keyſ":[{"kid":"a","kty":"RSA"}]}}`,
			expectErr: "missing the required 'keys' member",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var owner TrustMarkOwner
			err := json.Unmarshal([]byte(tc.entry), &owner)

			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("[%s] expected the entry to be refused, got sub %q with %d keys", tc.reference, owner.Sub, len(owner.JWKs.Keys))
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[%s] expected an error naming %s, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the entry to be accepted, got %v", tc.reference, err)
			}
			if owner.Sub != "https://owner.example.com" || len(owner.JWKs.Keys) != 1 {
				t.Errorf("[%s] expected the exact members to be read, got sub %q with %d keys", tc.reference, owner.Sub, len(owner.JWKs.Keys))
			}
		})
	}
}
