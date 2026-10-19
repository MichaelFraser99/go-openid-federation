package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func statementJSON(t *testing.T, extra string) string {
	t.Helper()
	base := fmt.Sprintf(`"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":%d,"exp":%d,"jwks":{"keys":[]}`,
		time.Now().Add(-time.Minute).UTC().Unix(), time.Now().Add(time.Hour).UTC().Unix())
	if extra == "" {
		return "{" + base + "}"
	}
	return "{" + base + "," + extra + "}"
}

func trustMarkFor(t *testing.T, trustMarkType string) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	head := encode(map[string]any{"typ": "trust-mark+jwt", "alg": "RS256", "kid": "k"})
	body := encode(map[string]any{
		"iss":             "https://tm.example.com",
		"sub":             "https://leaf.example.com",
		"trust_mark_type": trustMarkType,
		"iat":             time.Now().UTC().Unix(),
	})
	return head + "." + body + ".signature"
}

func TestEntityStatement_ClaimSyntax(t *testing.T) {
	validMark := trustMarkFor(t, "https://tm.example.com/a")

	tests := []struct {
		name      string
		step      string
		claims    string
		expectErr string
	}{
		// 3.2 step 5 and 1.2 - iss and sub must be Entity Identifiers (#106)
		{
			name:      "iss that is not an entity identifier",
			step:      "3.2 step 5",
			claims:    `"iss":"http://leaf.example.com"`,
			expectErr: "'iss' claim is not a valid entity identifier",
		},
		{
			name:      "sub with a query component",
			step:      "1.2",
			claims:    `"sub":"https://leaf.example.com/?x=1"`,
			expectErr: "'sub' claim is not a valid entity identifier",
		},
		{
			name:      "sub that is not a url",
			step:      "3.2 step 4",
			claims:    `"sub":"leaf"`,
			expectErr: "'sub' claim is not a valid entity identifier",
		},

		// 3.2 step 7 - the current time must be after iat (#65)
		{
			name:      "iat in the future beyond the leeway",
			step:      "3.2 step 7",
			claims:    fmt.Sprintf(`"iat":%d`, time.Now().Add(24*time.Hour).UTC().Unix()),
			expectErr: "issued in the future",
		},
		{
			name:   "iat inside the clock skew leeway is accepted",
			step:   "3.2 step 7",
			claims: fmt.Sprintf(`"iat":%d`, time.Now().Add(30*time.Second).UTC().Unix()),
		},

		// 3.2 step 9 and RFC 7517 - jwks must be a JWK Set (#107)
		{
			name:      "jwks with no keys member",
			step:      "3.2 step 9",
			claims:    `"jwks":{}`,
			expectErr: "missing required 'keys' member",
		},
		{
			name:      "jwks with a null keys member",
			step:      "3.2 step 9",
			claims:    `"jwks":{"keys":null}`,
			expectErr: "'keys' must be an array",
		},
		{
			name:      "jwks that is not an object",
			step:      "3.2 step 9",
			claims:    `"jwks":"keys"`,
			expectErr: "must be a JSON object",
		},

		// 3.1.2 - authority_hints must not be the empty array (#113)
		{
			name:      "empty authority_hints",
			step:      "3.1.2",
			claims:    `"authority_hints":[]`,
			expectErr: "must not be the empty array",
		},
		{
			name:      "authority_hints with an invalid identifier",
			step:      "3.2 step 14",
			claims:    `"authority_hints":["http://ta.example.com"]`,
			expectErr: "contains invalid entity identifier",
		},

		// 3.1.2 and 3.2 step 15 - trust_anchor_hints (#116)
		{
			name:   "valid trust_anchor_hints are kept",
			step:   "3.1.2",
			claims: `"trust_anchor_hints":["https://ta.example.com"]`,
		},
		{
			name:      "empty trust_anchor_hints",
			step:      "3.1.2",
			claims:    `"trust_anchor_hints":[]`,
			expectErr: "must not be the empty array",
		},
		{
			name:      "trust_anchor_hints that is not an array",
			step:      "3.2 step 15",
			claims:    `"trust_anchor_hints":"not-an-array"`,
			expectErr: "'trust_anchor_hints' claim is malformed",
		},
		{
			name:      "trust_anchor_hints with a non-string element",
			step:      "3.2 step 15",
			claims:    `"trust_anchor_hints":[42]`,
			expectErr: "contains malformed entity identifier",
		},

		// 3.2 step 13 and 13.4 - crit (#66, #109)
		{
			name:      "crit naming a claim defined by the specification",
			step:      "13.4",
			claims:    `"crit":["iss"]`,
			expectErr: "defined by this specification",
		},
		{
			name:      "crit that is not an array",
			step:      "3.2 step 13",
			claims:    `"crit":"urn:example:x"`,
			expectErr: "must be an array of strings",
		},
		{
			name:      "crit with a non-string element",
			step:      "3.2 step 13",
			claims:    `"crit":[1]`,
			expectErr: "must be an array of strings",
		},
		{
			name:      "empty crit",
			step:      "13.4",
			claims:    `"crit":[]`,
			expectErr: "must not be the empty array",
		},
		{
			name:      "crit with duplicate entries",
			step:      "13.4",
			claims:    `"crit":["urn:example:a","urn:example:a"],"urn:example:a":true`,
			expectErr: "duplicate entries",
		},
		{
			name:      "crit naming a claim absent from the statement",
			step:      "13.4",
			claims:    `"crit":["urn:example:absent"]`,
			expectErr: "not present in the entity statement",
		},
		{
			name:      "crit naming an understood-by-nobody extension claim",
			step:      "3.2 step 13",
			claims:    `"crit":["urn:example:unknown"],"urn:example:unknown":true`,
			expectErr: "none of which this implementation understands",
		},

		// 3.1.3 and 3.2 step 18 - metadata_policy_crit (#101)
		{
			name:      "empty metadata_policy_crit",
			step:      "3.1.3",
			claims:    `"metadata_policy_crit":[]`,
			expectErr: "must not be the empty array",
		},
		{
			name:      "metadata_policy_crit that is not an array",
			step:      "3.2 step 18",
			claims:    `"metadata_policy_crit":"regexp"`,
			expectErr: "must be an array of strings",
		},
		{
			name:      "metadata_policy_crit with a non-string element",
			step:      "3.2 step 18",
			claims:    `"metadata_policy_crit":[1]`,
			expectErr: "must be an array of strings",
		},
		{
			name:      "metadata_policy_crit naming a standard operator",
			step:      "3.2 step 18",
			claims:    `"metadata_policy_crit":["value"]`,
			expectErr: "defined by this specification",
		},
		{
			name:   "metadata_policy_crit naming an additional operator is syntactically valid",
			step:   "3.1.3",
			claims: `"metadata_policy_crit":["regexp"]`,
		},

		// 3.2 step 23 - source_endpoint must be a URL (#114)
		{
			name:      "source_endpoint that is a number",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":42`,
			expectErr: "must be a string",
		},
		{
			name:      "source_endpoint that is an object",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":{}`,
			expectErr: "must be a string",
		},
		{
			name:      "source_endpoint that is not a url",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":"::not a url::"`,
			expectErr: "must be a valid absolute URL",
		},
		{
			name:   "a valid source_endpoint is kept",
			step:   "3.2 step 23",
			claims: `"source_endpoint":"https://ta.example.com/fetch"`,
		},

		// 3.2 step 22 - trust_mark_owners (#115)
		{
			name:      "trust_mark_owners that is a string",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":"garbage"`,
			expectErr: "must be a JSON object",
		},
		{
			name:      "trust_mark_owners entry missing sub",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"jwks":{"keys":[]}}}`,
			expectErr: "missing the required 'sub' member",
		},
		{
			name:      "trust_mark_owners entry missing jwks",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com"}}`,
			expectErr: "missing the required 'jwks' member",
		},
		{
			name:      "trust_mark_owners entry with a non-string sub",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":42,"jwks":{"keys":[]}}}`,
			expectErr: "malformed 'sub' member",
		},
		{
			name:      "trust_mark_owners entry whose sub is not an entity identifier",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"http://o.example.com","jwks":{"keys":[]}}}`,
			expectErr: "not a valid entity identifier",
		},
		{
			name:      "trust_mark_owners entry that is not an object",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":"https://o.example.com"}`,
			expectErr: "must be a JSON object",
		},
		{
			name:      "trust_mark_owners entry whose jwks has no keys",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com","jwks":{}}}`,
			expectErr: "no 'keys' array",
		},
		{
			name:      "trust_mark_owners entry whose jwks keys is not an array",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com","jwks":{"keys":"x"}}}`,
			expectErr: "whose 'keys' is not an array",
		},
		{
			name:   "a valid trust_mark_owners entry with extra members is kept",
			step:   "3.1.2",
			claims: `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com","jwks":{"keys":[]},"other":"allowed"}}`,
		},

		// 3.2 step 20 - trust_marks (#119)
		{
			name:      "trust_marks entry with no trust_mark",
			step:      "3.2 step 20",
			claims:    `"trust_marks":[{"trust_mark_type":"https://tm.example.com/a"}]`,
			expectErr: "requires a non-empty 'trust_mark' member",
		},
		{
			name:      "trust_marks entry with no trust_mark_type",
			step:      "3.2 step 20",
			claims:    fmt.Sprintf(`"trust_marks":[{"trust_mark":%q}]`, validMark),
			expectErr: "requires a non-empty 'trust_mark_type' member",
		},
		{
			name:      "trust_marks entry whose trust_mark is not a jwt",
			step:      "3.2 step 20",
			claims:    `"trust_marks":[{"trust_mark_type":"https://tm.example.com/a","trust_mark":"hello"}]`,
			expectErr: "must be a signed JWT",
		},
		{
			name:      "trust_marks entry whose holder type differs from the signed type",
			step:      "3.2 step 20",
			claims:    fmt.Sprintf(`"trust_marks":[{"trust_mark_type":"https://tm.example.com/b","trust_mark":%q}]`, validMark),
			expectErr: "does not match the 'trust_mark_type' claim",
		},
		{
			name:   "a consistent trust_marks entry is kept",
			step:   "3.2 step 20",
			claims: fmt.Sprintf(`"trust_marks":[{"trust_mark_type":"https://tm.example.com/a","trust_mark":%q}]`, validMark),
		},

		// section 5 and 3.2 step 16 - null metadata values (#117)
		{
			name:      "an entity type with a null value",
			step:      "section 5",
			claims:    `"metadata":{"openid_relying_party":null}`,
			expectErr: "must be a JSON object",
		},
		{
			name:      "a metadata parameter with a null value",
			step:      "section 5",
			claims:    `"metadata":{"federation_entity":{"organization_name":null}}`,
			expectErr: "must not be null",
		},
		{
			name:      "an extension entity type with a null value",
			step:      "section 5",
			claims:    `"metadata":{"urn:example:type":null}`,
			expectErr: "must be a JSON object",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var statement EntityStatement
			err := json.Unmarshal([]byte(statementJSON(t, tc.claims)), &statement)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the statement to parse, got %v", tc.step, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error containing %q, got a parsed statement", tc.step, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
		})
	}
}
