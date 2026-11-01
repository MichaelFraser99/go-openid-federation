package model

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateAtCharacter_EveryBoundCutsOnACharacter(t *testing.T) {
	bounds := map[string]struct {
		limit    int
		truncate func(string) string
	}{
		"an error description": {limit: MaxErrorDescriptionBytes, truncate: TruncateForResponse},
		"a logged value":       {limit: MaxLoggedValueBytes, truncate: truncateLoggedValue},
		"any limit":            {limit: 64, truncate: func(value string) string { return TruncateAtCharacter(value, 64) }},
	}
	characters := map[string]string{
		"a two byte character":   "é",
		"a three byte character": "€",
		"a four byte character":  "😀",
	}

	for bound, b := range bounds {
		for name, character := range characters {
			t.Run(bound+", "+name+" across the limit", func(t *testing.T) {
				for offset := 1; offset < len(character); offset++ {
					prefix := strings.Repeat("a", b.limit-offset)
					got := b.truncate(prefix + character + "tail")
					if !utf8.ValidString(got) {
						t.Fatalf("offset %d: the truncated value is not valid UTF-8: it ends %q", offset, got[len(got)-8:])
					}
					if got != prefix+"..." {
						t.Errorf("offset %d: expected the cut just before the character, got %d bytes", offset, len(got))
					}
				}
			})
			t.Run(bound+", "+name+" ending exactly at the limit", func(t *testing.T) {
				prefix := strings.Repeat("a", b.limit-len(character))
				got := b.truncate(prefix + character + "tail")
				if got != prefix+character+"..." {
					t.Errorf("a character that fits must be kept, got %d bytes", len(got))
				}
			})
		}
		t.Run(bound+", a long run that is not UTF-8 after a short valid prefix keeps the limit", func(t *testing.T) {
			value := "abc" + strings.Repeat("\x80", b.limit*2)
			if got := b.truncate(value); len(got) != b.limit+len("...") {
				t.Errorf("expected the cut at the limit rather than back at the valid prefix, got %d bytes", len(got))
			}
		})
		t.Run(bound+", input that is not UTF-8 at the limit keeps the limit", func(t *testing.T) {
			value := strings.Repeat("\x80", b.limit*2)
			if got := b.truncate(value); len(got) != b.limit+len("...") {
				t.Errorf("expected the cut at the limit rather than a walk back through the whole value, got %d bytes", len(got))
			}
		})
	}
}

func TestTruncateForResponse_AnErrorDescriptionMarshalsWithoutAReplacementCharacter(t *testing.T) {
	description := TruncateForResponse(strings.Repeat("a", MaxErrorDescriptionBytes-1) + "é" + "tail")
	body, err := json.Marshal(map[string]string{"error_description": description})
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if strings.Contains(string(body), "�") || strings.Contains(string(body), `�`) {
		t.Errorf("the response carries U+FFFD, so the cut split a character: %s", body[len(body)-16:])
	}
}
