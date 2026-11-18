package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplyPolicyToMetadata_OneOfOnAnArrayNamesTheCause(t *testing.T) {
	tests := map[string]struct {
		parameter string
		policy    string
		metadata  map[string]any
		says      string
		want      any
	}{
		"scope present": {
			parameter: "scope", policy: `{"one_of":["openid"]}`,
			metadata: map[string]any{"scope": "openid"},
			says:     "one_of cannot be applied to scope, because policy operators process scope as an array of scope values",
		},
		"scope absent": {
			parameter: "scope", policy: `{"one_of":["openid"]}`,
			metadata: map[string]any{},
		},
		"another array parameter": {
			parameter: "response_types", policy: `{"one_of":["code"]}`,
			metadata: map[string]any{"response_types": []any{"code"}},
			says:     "one_of cannot be applied to a metadata parameter whose value is an array",
		},
		"a string parameter that matches": {
			parameter: "token_endpoint_auth_method", policy: `{"one_of":["private_key_jwt","none"]}`,
			metadata: map[string]any{"token_endpoint_auth_method": "none"},
			want:     "none",
		},
		"an object parameter that matches": {
			parameter: "x", policy: `{"one_of":[{"k":1},{"k":2}]}`,
			metadata: map[string]any{"x": map[string]any{"k": float64(2)}},
			want:     map[string]any{"k": float64(2)},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(`{"openid_relying_party":{"`+tc.parameter+`":`+tc.policy+`}}`), &policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
			err := applyPolicyToMetadata(tc.metadata, policy.OpenIDRelyingPartyMetadata)
			if tc.says != "" {
				if err == nil || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("[6.1.3] expected a policy error naming %q, got %v", tc.says, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the policy to apply, got %v", err)
			}
			got, present := tc.metadata[tc.parameter]
			if tc.want == nil {
				if present {
					t.Errorf("[6.1.3.1.4] expected no effect on an absent parameter, got %#v", got)
				}
				return
			}
			raw, _ := json.Marshal(got)
			want, _ := json.Marshal(tc.want)
			if string(raw) != string(want) {
				t.Errorf("expected %s, got %s", want, raw)
			}
		})
	}
}
