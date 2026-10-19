package model

import (
	"strings"
	"testing"
)

func TestTruncateForResponse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectLen int
		truncated bool
	}{
		{name: "a short value is unchanged", input: "a short reason", expectLen: 14},
		{name: "exactly at the limit is unchanged", input: strings.Repeat("a", MaxErrorDescriptionBytes), expectLen: MaxErrorDescriptionBytes},
		{name: "one over the limit is truncated", input: strings.Repeat("a", MaxErrorDescriptionBytes+1), expectLen: MaxErrorDescriptionBytes + 3, truncated: true},
		{name: "a megabyte is truncated", input: strings.Repeat("a", 1<<20), expectLen: MaxErrorDescriptionBytes + 3, truncated: true},
		{name: "an empty value is unchanged", input: "", expectLen: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateForResponse(tc.input)
			if len(got) != tc.expectLen {
				t.Errorf("expected %d bytes, got %d", tc.expectLen, len(got))
			}
			if tc.truncated && !strings.HasSuffix(got, "...") {
				t.Errorf("expected a truncated value to be marked, got %q", got[max(0, len(got)-8):])
			}
			if !tc.truncated && got != tc.input {
				t.Errorf("expected the value to pass through unchanged")
			}
		})
	}
}
