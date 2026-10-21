package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const harnessJwk = `{"kty":"EC","crv":"P-256","kid":"leaf","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`

func trustMarkWithoutType(t *testing.T) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	head := encode(map[string]any{"typ": "trust-mark+jwt", "alg": "RS256", "kid": "k"})
	body := encode(map[string]any{"iss": "https://tm.example.com", "sub": "https://leaf.example.com"})
	return head + "." + body + ".signature"
}

func statementJSON(t *testing.T, extra string) string {
	t.Helper()
	base := fmt.Sprintf(`"iss":"https://leaf.example.com","sub":"https://leaf.example.com","iat":%d,"exp":%d,"jwks":{"keys":[%s]}`,
		time.Now().Add(-time.Minute).UTC().Unix(), time.Now().Add(time.Hour).UTC().Unix(), harnessJwk)
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
		name        string
		step        string
		claims      string
		expectErr   string
		expectClass error
		assert      func(t *testing.T, statement EntityStatement)
	}{
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
			assert: func(t *testing.T, statement EntityStatement) {
				if statement.Iat <= time.Now().UTC().Unix() {
					t.Errorf("expected the future-dated iat to be kept, got %d", statement.Iat)
				}
			},
		},
		{
			name:      "iat beyond the clock skew leeway",
			step:      "3.2 step 7",
			claims:    fmt.Sprintf(`"iat":%d`, time.Now().Add(2*time.Minute).UTC().Unix()),
			expectErr: "issued in the future",
		},
		{
			name:      "iat that is negative",
			step:      "3.2 step 7",
			claims:    `"iat":-99`,
			expectErr: "must not be negative",
		},
		{
			name:      "iat outside the representable range",
			step:      "3.2 step 7",
			claims:    `"iat":1e308`,
			expectErr: "outside the representable range",
		},
		{
			name:      "exp outside the representable range",
			step:      "3.2 step 8",
			claims:    `"exp":1e308`,
			expectErr: "outside the representable range",
		},
		{
			name:      "exp that is negative",
			step:      "3.2 step 8",
			claims:    `"exp":-1`,
			expectErr: "must not be negative",
		},
		{
			name:   "exp inside the clock skew leeway is accepted",
			step:   "3.2 step 8",
			claims: fmt.Sprintf(`"iat":%d,"exp":%d`, time.Now().Add(-time.Hour).UTC().Unix(), time.Now().Add(-30*time.Second).UTC().Unix()),
			assert: func(t *testing.T, statement EntityStatement) {
				if statement.Exp >= time.Now().UTC().Unix() {
					t.Errorf("expected the recently expired exp to be kept, got %d", statement.Exp)
				}
			},
		},
		{
			name:      "exp beyond the clock skew leeway",
			step:      "3.2 step 8",
			claims:    fmt.Sprintf(`"exp":%d`, time.Now().Add(-2*time.Minute).UTC().Unix()),
			expectErr: "has expired",
		},
		{
			name:      "iat after exp",
			step:      "3.2 steps 7 and 8",
			claims:    fmt.Sprintf(`"iat":%d,"exp":%d`, time.Now().Add(30*time.Second).UTC().Unix(), time.Now().Add(10*time.Second).UTC().Unix()),
			expectErr: "must be before its 'exp' claim",
		},
		{
			name:      "iat equal to exp",
			step:      "3.2 steps 7 and 8",
			claims:    fmt.Sprintf(`"iat":%d,"exp":%d`, time.Now().Add(10*time.Second).UTC().Unix(), time.Now().Add(10*time.Second).UTC().Unix()),
			expectErr: "must be before its 'exp' claim",
		},

		{
			name:        "metadata that is null",
			step:        "section 5",
			claims:      `"metadata":null`,
			expectErr:   "must not be null",
			expectClass: ErrInvalidMetadata,
		},
		{
			name:        "metadata_policy that is null",
			step:        "3.2 step 17",
			claims:      `"metadata_policy":null`,
			expectErr:   "must not be null",
			expectClass: ErrInvalidMetadata,
		},
		{
			name:      "jwks with no keys member",
			step:      "3.2 step 9",
			claims:    `"jwks":{}`,
			expectErr: "is missing the required 'keys' member",
		},
		{
			name:      "jwks with a null keys member",
			step:      "3.2 step 9",
			claims:    `"jwks":{"keys":null}`,
			expectErr: "has a 'keys' member that is not an array",
		},
		{
			name:      "jwks that is not an object",
			step:      "3.2 step 9",
			claims:    `"jwks":"keys"`,
			expectErr: "must be a JSON object",
		},

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

		{
			name:   "valid trust_anchor_hints are kept",
			step:   "3.1.2",
			claims: `"trust_anchor_hints":["https://ta.example.com"]`,
			assert: func(t *testing.T, statement EntityStatement) {
				if len(statement.TrustAnchorHints) != 1 || statement.TrustAnchorHints[0] != "https://ta.example.com" {
					t.Errorf("expected the parsed trust_anchor_hints to be kept, got %v", statement.TrustAnchorHints)
				}
			},
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
			name:      "metadata_policy_crit naming an operator this implementation cannot process",
			step:      "3.2 step 18",
			claims:    `"metadata_policy_crit":["regexp"]`,
			expectErr: "none of which this implementation understands",
		},

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
			expectErr: "is not a valid url",
		},
		{
			name:   "a valid source_endpoint is kept",
			step:   "3.2 step 23",
			claims: `"source_endpoint":"https://ta.example.com/fetch"`,
			assert: func(t *testing.T, statement EntityStatement) {
				if statement.SourceEndpoint == nil || *statement.SourceEndpoint != "https://ta.example.com/fetch" {
					t.Errorf("expected the parsed source_endpoint to be kept, got %v", statement.SourceEndpoint)
				}
			},
		},
		{
			name:      "source_endpoint over plain http",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":"http://ta.example.com/fetch"`,
			expectErr: "must use the 'https' scheme",
		},
		{
			name:      "source_endpoint carrying a fragment",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":"https://ta.example.com/fetch#frag"`,
			expectErr: "must not contain a fragment component",
		},
		{
			name:   "source_endpoint carrying a query is accepted",
			step:   "3.2 step 23 and 5.1.1",
			claims: `"source_endpoint":"https://ta.example.com/fetch?sub=x"`,
			assert: func(t *testing.T, statement EntityStatement) {
				if statement.SourceEndpoint == nil || *statement.SourceEndpoint != "https://ta.example.com/fetch?sub=x" {
					t.Errorf("expected the query to be kept, got %v", statement.SourceEndpoint)
				}
			},
		},
		{
			name:      "source_endpoint carrying userinfo",
			step:      "1.2",
			claims:    `"source_endpoint":"https://ta.example.com@evil.example/fetch"`,
			expectErr: "must not contain a userinfo component",
		},
		{
			name:      "source_endpoint with no host",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":"https:///fetch"`,
			expectErr: "must be a valid absolute URL",
		},
		{
			name:      "source_endpoint over a non-http scheme",
			step:      "3.2 step 23",
			claims:    `"source_endpoint":"ftp://ta.example.com/fetch"`,
			expectErr: "must use the 'https' scheme",
		},

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
			expectErr: "is missing the required 'keys' member",
		},
		{
			name:      "trust_mark_owners entry whose jwks keys is not an array",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com","jwks":{"keys":"x"}}}`,
			expectErr: "has a 'keys' member that is not an array",
		},
		{
			name:   "a valid trust_mark_owners entry with extra members is kept",
			step:   "3.1.2",
			claims: `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com","jwks":{"keys":[]},"other":"allowed"}}`,
			assert: func(t *testing.T, statement EntityStatement) {
				owner, present := statement.TrustMarkOwners["https://tm.example.com/a"]
				if !present {
					t.Fatalf("expected the parsed trust_mark_owners entry to be kept, got %v", statement.TrustMarkOwners)
				}
				if owner.Sub != "https://o.example.com" {
					t.Errorf("expected sub to be kept, got %q", owner.Sub)
				}
				if owner.AdditionalClaims["other"] != "allowed" {
					t.Errorf("expected the extra member to be kept, got %v", owner.AdditionalClaims)
				}
				raw, err := json.Marshal(statement.TrustMarkOwners)
				if err != nil {
					t.Fatalf("failed to re-marshal trust_mark_owners: %v", err)
				}
				if !strings.Contains(string(raw), `"other":"allowed"`) {
					t.Errorf("expected the extra member to survive re-marshalling, got %s", raw)
				}
			},
		},

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
			assert: func(t *testing.T, statement EntityStatement) {
				if len(statement.TrustMarks) != 1 {
					t.Fatalf("expected one parsed trust mark, got %v", statement.TrustMarks)
				}
				if statement.TrustMarks[0].TrustMarkType != "https://tm.example.com/a" {
					t.Errorf("expected the trust_mark_type to be kept, got %q", statement.TrustMarks[0].TrustMarkType)
				}
				if statement.TrustMarks[0].TrustMark != validMark {
					t.Errorf("expected the trust_mark to be kept, got %q", statement.TrustMarks[0].TrustMark)
				}
			},
		},
		{
			name:      "a trust_mark whose body has no trust_mark_type",
			step:      "3.2 step 20",
			claims:    fmt.Sprintf(`"trust_marks":[{"trust_mark_type":"https://tm.example.com/a","trust_mark":%q}]`, trustMarkWithoutType(t)),
			expectErr: "has no 'trust_mark_type' claim",
		},
		{
			name:      "trust_mark_owners entry whose jwks is not an object",
			step:      "3.2 step 22",
			claims:    `"trust_mark_owners":{"https://tm.example.com/a":{"sub":"https://o.example.com","jwks":"not an object"}}`,
			expectErr: "'jwks' member that must be a JSON object",
		},
		{
			name:      "iat at the representable boundary",
			step:      "3.2 step 7",
			claims:    `"iat":4611686018427387904`,
			expectErr: "outside the representable range",
		},
		{
			name:      "a trust_mark with more than three segments",
			step:      "3.2 step 20",
			claims:    `"trust_marks":[{"trust_mark_type":"https://tm.example.com/a","trust_mark":"a.b.c.d"}]`,
			expectErr: "must be a signed JWT",
		},

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
				if tc.assert == nil {
					t.Fatalf("[%s] a positive case must assert what was parsed", tc.step)
				}
				tc.assert(t, statement)
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected an error containing %q, got a parsed statement", tc.step, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
			if tc.expectClass != nil && !errors.Is(err, tc.expectClass) {
				t.Fatalf("[%s] expected the error to carry the %T class, got %v", tc.step, tc.expectClass, err)
			}
		})
	}
}
