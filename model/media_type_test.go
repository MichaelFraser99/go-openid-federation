package model

import "testing"

func TestIsEntityStatementMediaType(t *testing.T) {
	tests := map[string]struct {
		contentType string
		accepted    bool
	}{
		"the media type":                                {"application/entity-statement+jwt", true},
		"the media type in another case":                {"Application/Entity-Statement+JWT", true},
		"the media type with a parameter":               {"application/entity-statement+jwt; charset=utf-8", true},
		"the media type with surrounding space":         {" application/entity-statement+jwt ", true},
		"another type naming it in a parameter":         {"text/html; x=application/entity-statement+jwt", false},
		"a longer subtype":                              {"application/entity-statement+jwtx", false},
		"a shorter subtype":                             {"application/entity-statement", false},
		"the generic jwt type":                          {"application/jwt", false},
		"the media type with a malformed parameter":     {"application/entity-statement+jwt; =x", false},
		"the media type followed by another media type": {"application/entity-statement+jwt, text/html", false},
		"no content type":                               {"", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsEntityStatementMediaType(tc.contentType); got != tc.accepted {
				t.Errorf("[RFC 9110 8.3.1] %q: expected accepted=%v, got %v", tc.contentType, tc.accepted, got)
			}
		})
	}
}
