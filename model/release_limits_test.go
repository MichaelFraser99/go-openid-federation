package model

import (
	"testing"
	"time"
)

func TestConfiguration_TrustMarkLimit(t *testing.T) {
	tests := map[string]struct {
		configured int
		expect     int
	}{
		"zero applies the default":      {configured: 0, expect: DefaultMaxTrustMarks},
		"negative applies the default":  {configured: -1, expect: DefaultMaxTrustMarks},
		"an explicit value is honoured": {configured: 3, expect: 3},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Configuration{MaxTrustMarks: tc.configured}
			if got := cfg.TrustMarkLimit(); got != tc.expect {
				t.Errorf("expected %d, got %d", tc.expect, got)
			}
		})
	}
	if DefaultMaxTrustMarks != 64 {
		t.Errorf("the README documents a default of 64 trust marks, got %d", DefaultMaxTrustMarks)
	}
}

func TestConfiguration_ResolveTimeLimit(t *testing.T) {
	tests := map[string]struct {
		configured time.Duration
		expect     time.Duration
	}{
		"zero applies the default":      {configured: 0, expect: DefaultMaxResolveTime},
		"negative applies the default":  {configured: -time.Second, expect: DefaultMaxResolveTime},
		"an explicit value is honoured": {configured: 5 * time.Second, expect: 5 * time.Second},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Configuration{MaxResolveTime: tc.configured}
			if got := cfg.ResolveTimeLimit(); got != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, got)
			}
		})
	}
	if DefaultMaxResolveTime != 30*time.Second {
		t.Errorf("the README documents a default of 30s, got %v", DefaultMaxResolveTime)
	}
}
