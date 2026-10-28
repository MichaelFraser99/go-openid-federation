package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

type longLogValuer struct{ text string }

func (v longLogValuer) LogValue() slog.Value { return slog.StringValue(v.text) }

func TestConfiguration_LogsBoundEveryValue(t *testing.T) {
	const marker = "LOGGED-TAIL-MARKER"
	long := strings.Repeat("v", 2*MaxLoggedValueBytes) + marker
	exact := strings.Repeat("e", MaxLoggedValueBytes)
	selfReferencing := map[string]any{}
	selfReferencing["self"] = selfReferencing

	tests := map[string]struct {
		args   []any
		key    string
		expect any
		bound  bool
	}{
		"a short string is kept":                {args: []any{slog.String("v", "short")}, key: "v", expect: "short"},
		"a string at the limit is kept":         {args: []any{slog.String("v", exact)}, key: "v", expect: exact},
		"a string one byte over is truncated":   {args: []any{slog.String("v", exact+"x")}, key: "v", expect: exact + "..."},
		"a long string is truncated":            {args: []any{slog.String("v", long)}, key: "v", bound: true},
		"a long key is truncated":               {args: []any{slog.String(long, "v")}, bound: true},
		"a long string in a group is truncated": {args: []any{slog.Group("g", slog.String("v", long))}, bound: true},
		"a small slice keeps its structure":     {args: []any{slog.Any("v", []string{"a", "b"})}, key: "v", expect: []any{"a", "b"}},
		"a large slice is truncated":            {args: []any{slog.Any("v", []string{long, long})}, key: "v", bound: true},
		"a large map is truncated":              {args: []any{slog.Any("v", map[string]any{"k": long})}, key: "v", bound: true},
		"a long error is truncated":             {args: []any{slog.Any("v", errors.New(long))}, key: "v", bound: true},
		"a long LogValuer is truncated":         {args: []any{slog.Any("v", longLogValuer{text: long})}, key: "v", bound: true},
		"a long raw pair value is truncated":    {args: []any{"v", long}, key: "v", bound: true},
		"a number is kept":                      {args: []any{slog.Int("v", 7)}, key: "v", expect: float64(7)},
		"a boolean is kept":                     {args: []any{slog.Bool("v", true)}, key: "v", expect: true},
		"a self-referencing map is named":       {args: []any{slog.Any("v", selfReferencing)}, key: "v", expect: "a map[string]interface {} that cannot be logged"},
	}

	for name, tc := range tests {
		for _, level := range []string{"info", "error"} {
			t.Run(name+" at "+level, func(t *testing.T) {
				var logs bytes.Buffer
				cfg := Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
				if level == "info" {
					cfg.LogInfo(context.Background(), "message", tc.args...)
				} else {
					cfg.LogError(context.Background(), "message", tc.args...)
				}

				raw := logs.String()
				if strings.Contains(raw, marker) {
					t.Fatalf("the tail of a %d byte value reached the log", len(long))
				}
				if len(raw) > 4*MaxLoggedValueBytes {
					t.Errorf("the record is %d bytes, more than a bounded value allows", len(raw))
				}
				if tc.key == "" || tc.bound {
					return
				}
				var record map[string]any
				if err := json.Unmarshal([]byte(raw), &record); err != nil {
					t.Fatalf("failed to parse the record: %v", err)
				}
				got, _ := json.Marshal(record[tc.key])
				want, _ := json.Marshal(tc.expect)
				if string(got) != string(want) {
					t.Errorf("expected %s, got %s", want, got)
				}
			})
		}
	}
}

type countingMarshaler struct{ calls *int }

func (c countingMarshaler) MarshalJSON() ([]byte, error) {
	*c.calls++
	return []byte(`"counted"`), nil
}

func TestConfiguration_LogsDoNoWorkForADisabledLevel(t *testing.T) {
	tests := map[string]struct {
		level      slog.Level
		logError   bool
		expectWork bool
	}{
		"info with info enabled":   {level: slog.LevelInfo, expectWork: true},
		"info with only errors on": {level: slog.LevelError},
		"error with errors on":     {level: slog.LevelError, logError: true, expectWork: true},
		"error above every level":  {level: slog.LevelError + 4, logError: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			calls := 0
			cfg := Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: tc.level}))}
			if tc.logError {
				cfg.LogError(context.Background(), "message", slog.Any("v", countingMarshaler{calls: &calls}))
			} else {
				cfg.LogInfo(context.Background(), "message", slog.Any("v", countingMarshaler{calls: &calls}))
			}
			if !tc.expectWork && (calls != 0 || logs.Len() != 0) {
				t.Errorf("a disabled level marshalled the value %d times and wrote %d bytes", calls, logs.Len())
			}
			if tc.expectWork && calls == 0 {
				t.Errorf("an enabled level did not bound the value")
			}
		})
	}
}

func TestTruncateLoggedValue_CutsOnACharacterBoundary(t *testing.T) {
	tests := map[string]string{
		"a two byte character":   "é",
		"a three byte character": "€",
		"a four byte character":  "😀",
	}

	for name, character := range tests {
		for offset := 1; offset < len(character); offset++ {
			t.Run(name, func(t *testing.T) {
				prefix := strings.Repeat("a", MaxLoggedValueBytes-offset)
				truncated := truncateLoggedValue(prefix + character + strings.Repeat("b", 64))
				if !utf8.ValidString(truncated) {
					t.Fatalf("the truncated value is not valid UTF-8: it ends %q", truncated[len(truncated)-8:])
				}
				if truncated != prefix+"..." {
					t.Errorf("expected the cut just before the character, got a value of %d bytes", len(truncated))
				}
			})
		}
	}
}
