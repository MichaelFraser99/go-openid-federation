package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMetadataPolicy_OneOfOnScopeNamesEachEntityType(t *testing.T) {
	tests := map[string]struct {
		policy string
		want   []string
	}{
		"no policy":                   {policy: `{}`},
		"one_of on another parameter": {policy: `{"openid_relying_party":{"response_types":{"one_of":["code"]}}}`},
		"subset_of on scope":          {policy: `{"openid_relying_party":{"scope":{"subset_of":["openid"]}}}`},
		"one_of on scope in several types, an extension type included": {
			policy: `{"x_custom":{"scope":{"one_of":["a"]}},"openid_relying_party":{"scope":{"one_of":["openid"],"subset_of":["openid"]}},"oauth_client":{"scope":{"default":"a"}}}`,
			want:   []string{"openid_relying_party", "x_custom"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
			if got := policy.OneOfOnScope(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
