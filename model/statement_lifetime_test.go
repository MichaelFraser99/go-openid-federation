package model

import (
	"strings"
	"testing"
	"time"
)

func TestResolveStatementLifetime(t *testing.T) {
	tests := []struct {
		name       string
		configured time.Duration
		expect     time.Duration
		expectErr  string
	}{
		{name: "an explicit lifetime is used", configured: 2 * time.Hour, expect: 2 * time.Hour},
		{name: "exactly one second is used", configured: time.Second, expect: time.Second},
		{name: "zero falls back to the default", configured: 0, expect: time.Hour},
		{name: "a sub second lifetime is refused", configured: 400 * time.Millisecond, expectErr: "must be at least one second"},
		{name: "a one nanosecond lifetime is refused", configured: time.Nanosecond, expectErr: "must be at least one second"},
		{name: "just under one second is refused", configured: 999 * time.Millisecond, expectErr: "must be at least one second"},
		{name: "a negative lifetime is refused", configured: -time.Second, expectErr: "must not be negative"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveStatementLifetime("TestLifetime", tc.configured, time.Hour)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got %s", tc.expectErr, got)
				}
				if !strings.Contains(err.Error(), tc.expectErr) || !strings.Contains(err.Error(), "TestLifetime") {
					t.Fatalf("expected an error naming the field and %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got != tc.expect {
				t.Errorf("expected %s, got %s", tc.expect, got)
			}
		})
	}
}
