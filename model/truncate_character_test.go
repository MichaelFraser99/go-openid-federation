package model

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/MichaelFraser99/go-openid-federation/internal/truncate"
)

func TestTruncateAtCharacter_EveryBoundCutsOnACharacter(t *testing.T) {
	bounds := map[string]struct {
		limit    int
		truncate func(string) string
	}{
		"an error description": {limit: truncate.MaxErrorDescriptionBytes, truncate: truncate.TruncateForResponse},
		"a logged value":       {limit: MaxLoggedValueBytes, truncate: truncateLoggedValue},
		"any limit":            {limit: 64, truncate: func(value string) string { return truncate.TruncateAtCharacter(value, 64) }},
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
	description := truncate.TruncateForResponse(strings.Repeat("a", truncate.MaxErrorDescriptionBytes-1) + "é" + "tail")
	body, err := json.Marshal(map[string]string{"error_description": description})
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if strings.Contains(string(body), "�") || strings.Contains(string(body), `�`) {
		t.Errorf("the response carries U+FFFD, so the cut split a character: %s", body[len(body)-16:])
	}
}

func TestTruncateAtCharacter_ALimitBelowOneKeepsNothing(t *testing.T) {
	tests := map[string]struct {
		value string
		limit int
		want  string
	}{
		"a zero limit":                         {value: "abc", limit: 0, want: "..."},
		"a limit of minus one":                 {value: "abc", limit: -1, want: "..."},
		"a large negative limit":               {value: "abc", limit: -100, want: "..."},
		"the lowest int":                       {value: "abc", limit: math.MinInt, want: "..."},
		"an empty value with a negative limit": {value: "", limit: -1, want: ""},
		"a value that starts mid-character":    {value: "\x80abc", limit: -1, want: "..."},
		"a multi-byte value":                   {value: "\u00e9t\u00e9", limit: -1, want: "..."},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := truncate.TruncateAtCharacter(tc.value, tc.limit); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
