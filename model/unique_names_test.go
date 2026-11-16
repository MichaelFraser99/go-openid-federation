package model

import (
	"strings"
	"testing"
)

func TestVerifyUniqueNames_JudgesTheTopLevelOnly(t *testing.T) {
	tests := map[string]struct {
		object   string
		repeated bool
	}{
		"no repeat":                                       {object: `{"a":1,"b":2}`},
		"a repeat at the top level":                       {object: `{"a":1,"a":1}`, repeated: true},
		"a repeat with other members":                     {object: `{"a":1,"b":{"c":1},"a":2}`, repeated: true},
		"a repeat in a nested object":                     {object: `{"a":{"b":1,"b":2}}`},
		"a repeat inside an array":                        {object: `{"a":[{"b":1,"b":2}]}`},
		"names differing only in case":                    {object: `{"iss":1,"ISS":2}`},
		"two invalid UTF-8 names that decode to one name": {object: `{"a` + "\xff" + `":1,"a` + "\xfe" + `":2}`, repeated: true},
		"a number too large for a float":                  {object: `{"a":1e999,"b":1e999}`},
		"an empty object":                                 {object: `{}`},
		"not an object":                                   {object: `[1,1]`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			header := VerifyUniqueHeaderParameters([]byte(tc.object))
			claims := VerifyUniqueClaimNames([]byte(tc.object))
			if (header != nil) != tc.repeated || (claims != nil) != tc.repeated {
				t.Fatalf("expected repeated=%v, got header %v and claims %v", tc.repeated, header, claims)
			}
			if tc.repeated && (!strings.Contains(header.Error(), "RFC 7515 section 4") || !strings.Contains(claims.Error(), "RFC 7519 section 4")) {
				t.Errorf("expected each refusal to name its clause, got %v and %v", header, claims)
			}
		})
	}
}

func TestTrustMark_UnmarshalJSON_RefusesARepeatedClaim(t *testing.T) {
	var mark TrustMark
	err := mark.UnmarshalJSON([]byte(`{"iss":"https://a.example.com","sub":"https://b.example.com","trust_mark_type":"t","iat":1,"iss":"https://a.example.com"}`))
	if err == nil || !strings.Contains(err.Error(), "repeats a member name") {
		t.Fatalf("[RFC 7519 4] expected a repeated claim to be refused, got %v", err)
	}
}
