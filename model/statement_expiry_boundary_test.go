package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEntityStatement_TheExpiryAllowanceIsExactlySixtySeconds(t *testing.T) {
	tests := map[string]struct {
		offset int64
		valid  bool
	}{
		"an exp 59 seconds past is valid":    {offset: -59, valid: true},
		"an exp 60 seconds past has expired": {offset: -60, valid: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for attempt := 0; attempt < 5; attempt++ {
				now := time.Now().Unix()
				raw, err := json.Marshal(map[string]any{
					"iss": "https://leaf.example.com", "sub": "https://leaf.example.com",
					"iat": now - 3600, "exp": now + tc.offset,
					"jwks": map[string]any{"keys": []any{}},
				})
				if err != nil {
					t.Fatal(err)
				}
				var statement EntityStatement
				err = json.Unmarshal(raw, &statement)
				if time.Now().Unix() != now {
					continue
				}
				if tc.valid && err != nil {
					t.Fatalf("[RFC 7519 4.1.4] expected a statement %ds past its exp to be inside the allowance, got %v", -tc.offset, err)
				}
				if !tc.valid && err == nil {
					t.Fatalf("[RFC 7519 4.1.4] the current time must be before exp plus the allowance, so a statement %ds past its exp must have expired", -tc.offset)
				}
				return
			}
			t.Fatal("the wall-clock second ticked over on every attempt")
		})
	}
}

func TestChainHasExpired_TheAllowanceIsExactlySixtySeconds(t *testing.T) {
	tests := map[string]struct {
		offset  int64
		expired bool
	}{
		"an exp 59 seconds past": {offset: -59, expired: false},
		"an exp 60 seconds past": {offset: -60, expired: true},
		"an exp 61 seconds past": {offset: -61, expired: true},
		"an exp in the future":   {offset: 60, expired: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for attempt := 0; attempt < 5; attempt++ {
				now := time.Now().Unix()
				expired := ChainHasExpired(now + tc.offset)
				if time.Now().Unix() != now {
					continue
				}
				if expired != tc.expired {
					t.Fatalf("[RFC 7519 4.1.4] expected an exp %+ds from now to be expired %v, got %v", tc.offset, tc.expired, expired)
				}
				return
			}
			t.Fatal("the wall-clock second ticked over on every attempt")
		})
	}
}
