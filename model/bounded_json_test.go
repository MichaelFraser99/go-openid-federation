package model

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCountJSONValues_AgreesWithTheDecodedCount(t *testing.T) {
	tests := map[string]string{
		"a scalar":                    `"x"`,
		"a number":                    `1.5e300`,
		"null":                        `null`,
		"an empty object":             `{}`,
		"an empty array":              `[]`,
		"an object of scalars":        `{"a":1,"b":"two","c":true,"d":null}`,
		"keys that look like objects": `{"{":"[","}":"]"}`,
		"nested objects and arrays":   `{"a":{"b":[1,{"c":[[],{}]}]},"d":[{"e":{}}]}`,
		"an array of objects":         `[{"a":1},{"b":2},{"c":{"d":3}}]`,
		"an entity statement shape":   `{"iss":"https://a","sub":"https://a","iat":1,"exp":2,"jwks":{"keys":[{"kty":"EC","kid":"k"}]},"authority_hints":["https://b"]}`,
	}

	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			var decoded any
			if err := json.Unmarshal([]byte(document), &decoded); err != nil {
				t.Fatal(err)
			}
			expected := CountDecodedValues(decoded)
			count, exceeded := CountJSONValues([]byte(document), expected)
			if exceeded || count != expected {
				t.Errorf("expected %d values within a limit of %d, got %d (exceeded %v)", expected, expected, count, exceeded)
			}
			if _, exceeded := CountJSONValues([]byte(document), expected-1); !exceeded {
				t.Errorf("expected a limit of %d to be exceeded by %d values", expected-1, expected)
			}
		})
	}
}

func TestCountJSONValues_StopsReadingOnceTheLimitIsPassed(t *testing.T) {
	tests := map[string]struct {
		document string
		limit    int
	}{
		"a long array":         {document: "[" + strings.Repeat("1,", 100_000) + "1]", limit: 10},
		"a wide object":        {document: "{" + strings.Repeat(`"k":1,`, 100_000) + `"k":1}`, limit: 10},
		"deeply nested arrays": {document: strings.Repeat("[", 100_000) + strings.Repeat("]", 100_000), limit: 10},
		"a truncated array":    {document: "[" + strings.Repeat("1,", 100), limit: 10},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			count, exceeded := CountJSONValues([]byte(tc.document), tc.limit)
			if !exceeded {
				t.Fatalf("expected the limit of %d to be exceeded", tc.limit)
			}
			if count != tc.limit+1 {
				t.Errorf("expected counting to stop at %d, it reached %d", tc.limit+1, count)
			}
		})
	}
}

func TestCountJSONValues_LeavesMalformedInputToTheDecoder(t *testing.T) {
	tests := map[string]string{
		"empty input":            ``,
		"a bare word":            `nope`,
		"an unclosed object":     `{"a":1`,
		"a missing value":        `{"a":}`,
		"a trailing comma":       `[1,2,]`,
		"a number with no digit": `-`,
	}

	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, exceeded := CountJSONValues([]byte(document), 100); exceeded {
				t.Errorf("expected malformed input within the limit not to be reported as exceeding it")
			}
			if err := VerifyJSONValueCount([]byte(document), 100); err != nil {
				t.Errorf("expected malformed input to be left to the decoder, got %v", err)
			}
		})
	}
}

func TestVerifyJSONValueCount_NamesTheLimit(t *testing.T) {
	tests := map[string]struct {
		values    int
		limit     int
		expectErr bool
	}{
		"one under the limit": {values: 9, limit: 10},
		"at the limit":        {values: 10, limit: 10},
		"one over the limit":  {values: 11, limit: 10, expectErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			document := "[" + strings.TrimSuffix(strings.Repeat("0,", tc.values-1), ",") + "]"
			err := VerifyJSONValueCount([]byte(document), tc.limit)
			if !tc.expectErr {
				if err != nil {
					t.Errorf("expected %d values to pass a limit of %d, got %v", tc.values, tc.limit, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "10 JSON values") {
				t.Errorf("expected a refusal naming the limit of %d, got %v", tc.limit, err)
			}
		})
	}
}

func TestConfiguration_StatementBoundsDefaultWhenUnset(t *testing.T) {
	tests := map[string]struct {
		cfg          Configuration
		expectValues int
		expectHints  int
	}{
		"unset applies the defaults":    {expectValues: DefaultMaxStatementValues, expectHints: DefaultMaxAuthorityHints},
		"negative applies the defaults": {cfg: Configuration{MaxStatementValues: -1, MaxAuthorityHints: -1}, expectValues: DefaultMaxStatementValues, expectHints: DefaultMaxAuthorityHints},
		"configured values apply":       {cfg: Configuration{MaxStatementValues: 7, MaxAuthorityHints: 3}, expectValues: 7, expectHints: 3},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.cfg.StatementValuesLimit(); got != tc.expectValues {
				t.Errorf("expected a statement value limit of %d, got %d", tc.expectValues, got)
			}
			if got := tc.cfg.AuthorityHintsLimit(); got != tc.expectHints {
				t.Errorf("expected an authority hints limit of %d, got %d", tc.expectHints, got)
			}
		})
	}
}

func trustMarkHolding(values int) map[string]any {
	body := "[" + strings.TrimSuffix(strings.Repeat("0,", values-1), ",") + "]"
	encode := base64.RawURLEncoding.EncodeToString
	return map[string]any{"trust_mark_type": "t", "trust_mark": encode([]byte(`{"alg":"none"}`)) + "." + encode([]byte(body)) + "." + encode([]byte("sig"))}
}

func TestVerifyTrustMarkValueCount_SharesOneBudgetAcrossEveryMark(t *testing.T) {
	tests := map[string]struct {
		marks     []any
		expectErr bool
	}{
		"no trust marks":                         {},
		"one mark at the limit":                  {marks: []any{trustMarkHolding(10)}},
		"one mark past the limit":                {marks: []any{trustMarkHolding(11)}, expectErr: true},
		"marks that together reach the limit":    {marks: []any{trustMarkHolding(4), trustMarkHolding(6)}},
		"marks that together pass the limit":     {marks: []any{trustMarkHolding(6), trustMarkHolding(6)}, expectErr: true},
		"many small marks past the limit":        {marks: []any{trustMarkHolding(2), trustMarkHolding(2), trustMarkHolding(2), trustMarkHolding(2), trustMarkHolding(2), trustMarkHolding(1)}, expectErr: true},
		"entries that are not marks are skipped": {marks: []any{"x", 1, map[string]any{"trust_mark": 3}, map[string]any{"trust_mark": "a.b"}, map[string]any{"trust_mark": "a.!!.c"}, trustMarkHolding(10)}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{}
			if tc.marks != nil {
				claims["trust_marks"] = tc.marks
			}
			err := VerifyTrustMarkValueCount(claims, 10)
			if tc.expectErr != (err != nil) {
				t.Fatalf("expected an error %v, got %v", tc.expectErr, err)
			}
			if err != nil && !strings.Contains(err.Error(), "10 JSON values") {
				t.Errorf("expected the refusal to name the limit, got %v", err)
			}
		})
	}
}
