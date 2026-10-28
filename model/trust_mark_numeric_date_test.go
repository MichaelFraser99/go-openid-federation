package model

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestTrustMarkUnmarshal_ANumericDateIsHeldToTheRepresentableRange(t *testing.T) {
	below := math.Nextafter(maxNumericDate, 0)

	tests := map[string]struct {
		claim     string
		value     any
		absent    bool
		expectErr string
		expect    int64
	}{
		"an iat at the epoch":           {claim: "iat", value: 0, expect: 0},
		"an iat just below the range":   {claim: "iat", value: below, expect: int64(below)},
		"an iat at the range":           {claim: "iat", value: maxNumericDate, expectErr: "'iat' claim is outside the representable range"},
		"an iat beyond the range":       {claim: "iat", value: 1e19, expectErr: "'iat' claim is outside the representable range"},
		"an iat far beyond the range":   {claim: "iat", value: 1e30, expectErr: "'iat' claim is outside the representable range"},
		"a negative iat":                {claim: "iat", value: -1, expectErr: "'iat' claim must not be negative"},
		"an iat that is a string":       {claim: "iat", value: "1700000000", expectErr: "missing or invalid required field 'iat'"},
		"an absent iat":                 {claim: "iat", absent: true, expectErr: "missing or invalid required field 'iat'"},
		"an exp just below the range":   {claim: "exp", value: below, expect: int64(below)},
		"an exp at the range":           {claim: "exp", value: maxNumericDate, expectErr: "'exp' claim is outside the representable range"},
		"an exp beyond the range":       {claim: "exp", value: 1e19, expectErr: "'exp' claim is outside the representable range"},
		"an exp far beyond the range":   {claim: "exp", value: 1e30, expectErr: "'exp' claim is outside the representable range"},
		"a negative exp":                {claim: "exp", value: -1, expectErr: "'exp' claim must not be negative"},
		"an exp that is a string":       {claim: "exp", value: "1800000000", expectErr: "'exp' claim is malformed"},
		"an exp that is null":           {claim: "exp", value: nil, expectErr: "'exp' claim is malformed"},
		"an absent exp means no expiry": {claim: "exp", absent: true, expect: -1},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			body := map[string]any{
				"iss":             "https://issuer.example.com",
				"sub":             "https://leaf.example.com",
				"trust_mark_type": "https://issuer.example.com/marks/member",
				"iat":             float64(1700000000),
				"exp":             float64(1800000000),
			}
			if tc.absent {
				delete(body, tc.claim)
			} else {
				body[tc.claim] = tc.value
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}

			var mark TrustMark
			err = json.Unmarshal(raw, &mark)
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[RFC 7519 2] expected a refusal saying %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[RFC 7519 2] expected the trust mark to parse, got %v", err)
			}
			switch {
			case tc.claim == "iat":
				if mark.IssuedAt != tc.expect {
					t.Errorf("expected iat %d, got %d", tc.expect, mark.IssuedAt)
				}
			case tc.expect < 0:
				if mark.Expiry != nil {
					t.Errorf("expected no expiry, got %d", *mark.Expiry)
				}
			default:
				if mark.Expiry == nil || *mark.Expiry != tc.expect {
					t.Errorf("expected exp %d, got %v", tc.expect, mark.Expiry)
				}
			}
		})
	}
}
