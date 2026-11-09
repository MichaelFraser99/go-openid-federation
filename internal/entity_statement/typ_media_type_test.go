package entity_statement

import (
	"strings"
	"testing"
)

func TestValidateStatementHeader_JudgesTypAsOneASCIIMediaType(t *testing.T) {
	const jwtType = "entity-statement+jwt"
	tests := map[string]bool{
		jwtType:                  true,
		"application/" + jwtType: true,
		strings.ToUpper(jwtType): true,
		"Application/" + strings.ToUpper(jwtType):  true,
		strings.Replace(jwtType, "s", "\u017f", 1): false,
		"application/application/" + jwtType:       false,
		"/" + jwtType:                              false,
		"text/" + jwtType:                          false,
		jwtType + " ":                              false,
		jwtType[:len(jwtType)-1]:                   false,
		"jwt":                                      false,
		"":                                         false,
	}

	for typ, accepted := range tests {
		t.Run(typ, func(t *testing.T) {
			err := ValidateStatementHeader(map[string]any{"typ": typ, "alg": "RS256"})
			if accepted && err != nil {
				t.Errorf("[RFC 7515 4.1.9] %q names the media type application/%s, got %v", typ, jwtType, err)
			}
			if !accepted && err == nil {
				t.Errorf("[3.2 step 2] %q is not the media type application/%s compared with ASCII case folding, so it must be refused", typ, jwtType)
			}
		})
	}
}
