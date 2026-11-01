package entity_statement

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateHeaderValue_CutsOnACharacter(t *testing.T) {
	prefix := strings.Repeat("a", maxQuotedHeaderBytes-1)
	got := truncateHeaderValue(prefix + "é" + "tail")
	if !utf8.ValidString(got) {
		t.Fatalf("the truncated header value is not valid UTF-8: it ends %q", got[len(got)-8:])
	}
	if got != prefix+"..." {
		t.Errorf("expected the cut just before the character, got %d bytes", len(got))
	}
}
