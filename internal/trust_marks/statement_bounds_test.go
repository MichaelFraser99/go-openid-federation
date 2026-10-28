package trust_marks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func paddedToken(t *testing.T, head, body map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(head) + "." + encode(body) + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature"))
}

func paddingOf(values int) []any {
	padding := make([]any, values)
	for i := range padding {
		padding[i] = 0
	}
	return padding
}

func TestValidate_ATrustMarkOrDelegationHoldingTooManyValuesIsRefusedBeforeItsSignatureIsChecked(t *testing.T) {
	tests := map[string]struct {
		cfg        model.Configuration
		delegation bool
		headPad    int
		bodyPad    int
		expected   string
	}{
		"a trust mark with a padded header": {
			headPad:  model.DefaultMaxStatementValues,
			expected: fmt.Sprintf("the trust mark's JWT header holds more than the %d JSON values", model.DefaultMaxStatementValues),
		},
		"a trust mark with a padded body": {
			bodyPad:  model.DefaultMaxStatementValues,
			expected: fmt.Sprintf("the trust mark's JWT body holds more than the %d JSON values", model.DefaultMaxStatementValues),
		},
		"a trust mark past a configured limit": {
			cfg:      model.Configuration{MaxStatementValues: 100},
			bodyPad:  100,
			expected: "the trust mark's JWT body holds more than the 100 JSON values",
		},
		"a delegation with a padded header": {
			delegation: true,
			headPad:    model.DefaultMaxStatementValues,
			expected:   fmt.Sprintf("the trust mark's delegation header holds more than the %d JSON values", model.DefaultMaxStatementValues),
		},
		"a delegation with a padded body": {
			delegation: true,
			bodyPad:    model.DefaultMaxStatementValues,
			expected:   fmt.Sprintf("the trust mark's delegation body holds more than the %d JSON values", model.DefaultMaxStatementValues),
		},
		"a delegation past a configured limit": {
			cfg:        model.Configuration{MaxStatementValues: 100},
			delegation: true,
			bodyPad:    100,
			expected:   "the trust mark's delegation body holds more than the 100 JSON values",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			issuer := f.id("member")
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}})
			ta.TrustMarkOwners = map[string]model.TrustMarkOwner{rvType: dlgOwnerEntry(t, dlgOwner, rvKey(t), "owner-key")}

			head := map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}
			body := map[string]any{
				"iss": issuer, "sub": rvSub, "trust_mark_type": rvType,
				"iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix(),
			}
			if tc.headPad > 0 {
				head["pad"] = paddingOf(tc.headPad)
			}
			if tc.bodyPad > 0 {
				body["pad"] = paddingOf(tc.bodyPad)
			}

			token := paddedToken(t, head, body)
			if tc.delegation {
				head["typ"] = "trust-mark-delegation+jwt"
				head["kid"] = "owner-key"
				body["iss"] = string(dlgOwner)
				body["sub"] = issuer
				token = shapedMark(t, f, issuer, rvType, paddedToken(t, head, body))
			}

			cfg := tc.cfg
			cfg.HttpClient = f.server.Client()
			_, err := Validate(t.Context(), cfg, token, ValidateOptions{
				ExpectedType:             rvType,
				ExpectedSubject:          rvSub,
				AuthorizedIssuers:        []model.EntityIdentifier{model.EntityIdentifier(issuer)},
				TrustAnchor:              ta.Sub,
				TrustAnchorConfiguration: ta,
			}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected a refusal containing %q, got %v", tc.expected, err)
			}
		})
	}
}
