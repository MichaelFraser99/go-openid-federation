package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseConstraints_HoldsTheClaimToItsSyntax(t *testing.T) {
	tests := map[string]struct {
		value     any
		expectErr string
	}{
		"an empty object":                           {value: map[string]any{}},
		"every member, well formed":                 {value: map[string]any{"max_path_length": float64(2), "naming_constraints": map[string]any{"permitted": []any{".example.com"}, "excluded": []any{"east.example.com"}}, "allowed_entity_types": []any{"openid_provider"}}},
		"unknown members are ignored":               {value: map[string]any{"https://example.com/extension": "x", "naming_constraints": map[string]any{"https://example.com/sub": 1}}},
		"a max_path_length of zero":                 {value: map[string]any{"max_path_length": float64(0)}},
		"an empty allowed_entity_types":             {value: map[string]any{"allowed_entity_types": []any{}}},
		"an empty permitted list":                   {value: map[string]any{"naming_constraints": map[string]any{"permitted": []any{}}}, expectErr: "'permitted' must not be empty"},
		"an empty excluded list":                    {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{}}}},
		"a string":                                  {value: "x", expectErr: "'constraints' claim must be a JSON object"},
		"an array":                                  {value: []any{float64(1)}, expectErr: "'constraints' claim must be a JSON object"},
		"null":                                      {value: nil, expectErr: "'constraints' claim must be a JSON object"},
		"a max_path_length that is a string":        {value: map[string]any{"max_path_length": "two"}, expectErr: "'max_path_length' must be an integer"},
		"a fractional max_path_length":              {value: map[string]any{"max_path_length": 1.5}, expectErr: "'max_path_length' must be an integer"},
		"a negative max_path_length":                {value: map[string]any{"max_path_length": float64(-1)}, expectErr: "'max_path_length' must not be negative"},
		"an address where a domain name belongs":    {value: map[string]any{"naming_constraints": map[string]any{"permitted": []any{"192.0.2.1"}}}, expectErr: "'permitted' must hold fully qualified domain names"},
		"a domain ending in a number":               {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{".2.1"}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"a label starting with a hyphen":            {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{"-a.example.com"}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"a label ending with a hyphen":              {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{"a-.example.com"}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"a label longer than 63 octets":             {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{strings.Repeat("a", 64) + ".com"}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"a name longer than 253 octets":             {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{strings.Repeat("abcdefghi.", 25) + "abcd"}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"a name of exactly 253 octets":              {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{strings.Repeat("abcdefghi.", 24) + strings.Repeat("a", 9) + ".com"}}}},
		"a label of exactly 63 octets":              {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{strings.Repeat("a", 63) + ".com"}}}},
		"a hyphen inside a label":                   {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{"a-b.example.com"}}}},
		"a label that is mostly digits":             {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{"123.example.com"}}}},
		"naming_constraints that are a string":      {value: map[string]any{"naming_constraints": "example.com"}, expectErr: "'naming_constraints' must be a JSON object"},
		"a permitted member that is a string":       {value: map[string]any{"naming_constraints": map[string]any{"permitted": "example.com"}}, expectErr: "'permitted' must be an array of strings"},
		"an excluded entry that is a number":        {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{float64(1)}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"a URI where a domain name belongs":         {value: map[string]any{"naming_constraints": map[string]any{"permitted": []any{"https://example.com"}}}, expectErr: "'permitted' must hold fully qualified domain names"},
		"an empty domain name":                      {value: map[string]any{"naming_constraints": map[string]any{"permitted": []any{""}}}, expectErr: "'permitted' must hold fully qualified domain names"},
		"a lone period":                             {value: map[string]any{"naming_constraints": map[string]any{"permitted": []any{"."}}}, expectErr: "'permitted' must hold fully qualified domain names"},
		"an empty label":                            {value: map[string]any{"naming_constraints": map[string]any{"excluded": []any{"a..example.com"}}}, expectErr: "'excluded' must hold fully qualified domain names"},
		"allowed_entity_types that are a string":    {value: map[string]any{"allowed_entity_types": "openid_provider"}, expectErr: "'allowed_entity_types' must be an array of strings"},
		"an allowed entity type that is a number":   {value: map[string]any{"allowed_entity_types": []any{float64(1)}}, expectErr: "'allowed_entity_types' must be an array of non-empty strings"},
		"an allowed entity type that is empty":      {value: map[string]any{"allowed_entity_types": []any{""}}, expectErr: "'allowed_entity_types' must be an array of non-empty strings"},
		"allowed_entity_types naming the always-on": {value: map[string]any{"allowed_entity_types": []any{"federation_entity"}}, expectErr: "must not list 'federation_entity'"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConstraints(tc.value)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[6.2] expected the constraints to parse, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[3.2 step 19] expected a refusal containing %q, got %v", tc.expectErr, err)
			}
		})
	}
}

func TestParseConstraints_ALargeMaxPathLengthIsClamped(t *testing.T) {
	tests := map[string]struct {
		value  float64
		expect int
	}{
		"just below the clamp": {value: 2147483646, expect: 2147483646},
		"at the clamp":         {value: 2147483647, expect: 2147483647},
		"just above the clamp": {value: 2147483648, expect: 2147483647},
		"far above the clamp":  {value: 1e30, expect: 2147483647},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseConstraints(map[string]any{"max_path_length": tc.value})
			if err != nil {
				t.Fatalf("[6.2.1] any integer of zero or more is a valid max_path_length, got %v", err)
			}
			if *parsed.MaxPathLength != tc.expect {
				t.Errorf("expected %d, got %d", tc.expect, *parsed.MaxPathLength)
			}
		})
	}
}

func TestEntityStatement_RefusesMalformedConstraints(t *testing.T) {
	statement := map[string]any{
		"iss": "https://ta.example.com", "sub": "https://leaf.example.com",
		"iat": float64(1700000000), "exp": float64(4000000000),
		"jwks":        map[string]any{"keys": []any{}},
		"constraints": map[string]any{"max_path_length": float64(-1)},
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	var parsed EntityStatement
	if err := json.Unmarshal(raw, &parsed); err == nil || !strings.Contains(err.Error(), "'max_path_length' must not be negative") {
		t.Fatalf("[3.2 step 19] expected the statement to be refused for its constraints, got %v", err)
	}
}

func TestConstraints_RoundTripKeepsEveryDistinction(t *testing.T) {
	tests := map[string]map[string]any{
		"every member":                     {"max_path_length": float64(2), "naming_constraints": map[string]any{"permitted": []any{".example.com"}, "excluded": []any{"east.example.com"}}, "allowed_entity_types": []any{"openid_provider"}},
		"an empty allowed_entity_types":    {"allowed_entity_types": []any{}},
		"an empty excluded list":           {"naming_constraints": map[string]any{"excluded": []any{}}},
		"naming constraints with no lists": {"naming_constraints": map[string]any{}},
		"no members":                       {},
	}

	for name, original := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseConstraints(original)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(parsed)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, original) {
				t.Errorf("expected %v to serialise unchanged, got %s", original, raw)
			}
		})
	}
}

func TestMetadata_RetainEntityTypes(t *testing.T) {
	var absent *Metadata
	if absent.RetainEntityTypes(nil) != nil {
		t.Errorf("expected absent metadata to stay absent")
	}
}
