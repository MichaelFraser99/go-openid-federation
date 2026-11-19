package subordinate_statement

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestOneOfOnScope_NamesEachEntityTypeOfTheIssuedPolicy(t *testing.T) {
	tests := map[string]struct {
		policy string
		want   []string
	}{
		"no policy":                   {policy: `{}`},
		"one_of on another parameter": {policy: `{"openid_relying_party":{"response_types":{"one_of":["code"]}}}`},
		"subset_of on scope":          {policy: `{"openid_relying_party":{"scope":{"subset_of":["openid"]}}}`},
		"one_of on a parameter whose name only folds to scope": {policy: `{"openid_relying_party":{"SCOPE":{"one_of":["openid"]}}}`},
		"one_of on scope in several types, an extension type included": {
			policy: `{"x_custom":{"scope":{"one_of":["a"]}},"openid_relying_party":{"scope":{"one_of":["openid"],"subset_of":["openid"]}},"oauth_client":{"scope":{"default":"a"}}}`,
			want:   []string{"openid_relying_party", "x_custom"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy model.MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatalf("failed to write the policy: %v", err)
			}
			var issued any
			if err := json.Unmarshal(raw, &issued); err != nil {
				t.Fatalf("failed to read the written policy: %v", err)
			}
			for range 32 {
				if got := oneOfOnScope(issued); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("[6.1.3.1.4] expected %v, got %v", tc.want, got)
				}
			}
		})
	}
}

func TestOneOfOnScope_IgnoresAValueThatIsNotAPolicy(t *testing.T) {
	for name, issued := range map[string]any{
		"absent":                     nil,
		"an array":                   []any{"scope"},
		"an entity type as a string": map[string]any{"openid_relying_party": "scope"},
		"a parameter as an array":    map[string]any{"openid_relying_party": map[string]any{"scope": []any{"one_of"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := oneOfOnScope(issued); got != nil {
				t.Errorf("expected no entity types, got %v", got)
			}
		})
	}
}
