package model

import (
	"encoding/json"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/boundedjson"
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
			expected := countDecodedValues(decoded)
			count, exceeded := boundedjson.CountJSONValues([]byte(document), expected)
			if exceeded || count != expected {
				t.Errorf("expected %d values within a limit of %d, got %d (exceeded %v)", expected, expected, count, exceeded)
			}
			if _, exceeded := boundedjson.CountJSONValues([]byte(document), expected-1); !exceeded {
				t.Errorf("expected a limit of %d to be exceeded by %d values", expected-1, expected)
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
		"unset applies the defaults":        {expectValues: DefaultMaxStatementValues, expectHints: DefaultMaxAuthorityHints},
		"negative applies the defaults":     {cfg: Configuration{MaxStatementValues: -1, MaxAuthorityHints: -1}, expectValues: DefaultMaxStatementValues, expectHints: DefaultMaxAuthorityHints},
		"configured values apply":           {cfg: Configuration{MaxStatementValues: 7, MaxAuthorityHints: 3}, expectValues: 7, expectHints: 3},
		"a configured limit of one applies": {cfg: Configuration{MaxStatementValues: 1, MaxAuthorityHints: 1}, expectValues: 1, expectHints: 1},
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
