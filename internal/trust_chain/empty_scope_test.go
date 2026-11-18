package trust_chain

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_AnEmptyResolvedScopeIsRefused(t *testing.T) {
	tests := map[string]struct {
		scope       string
		policy      map[string]any
		entityTypes []string
		refused     bool
		expect      string
	}{
		"a subset_of with no overlap":                     {scope: "openid profile", policy: map[string]any{"subset_of": []any{"email"}}, refused: true},
		"a subject that publishes an empty scope":         {scope: ""},
		"a subset_of with an overlap":                     {scope: "openid profile", policy: map[string]any{"subset_of": []any{"openid email"}}, expect: "openid"},
		"a value that supplies a scope":                   {scope: "", policy: map[string]any{"value": "openid"}, expect: "openid"},
		"an empty scope on a type that was not asked for": {scope: "openid", policy: map[string]any{"subset_of": []any{"email"}}, entityTypes: []string{"federation_entity"}},
	}

	for _, entityType := range []string{"openid_relying_party", "oauth_client"} {
		for name, tc := range tests {
			t.Run(entityType+", "+name, func(t *testing.T) {
				refused := tc.refused || (tc.policy == nil && tc.scope == "")
				var subordinateExtra map[string]any
				if tc.policy != nil {
					subordinateExtra = map[string]any{"metadata_policy": map[string]any{entityType: map[string]any{"scope": tc.policy}}}
				}
				chain := chainWithClaims(t, map[string]any{
					"federation_entity": map[string]any{"organization_name": "Leaf"},
					entityType:          map[string]any{"redirect_uris": []any{"https://leaf.example.com/cb"}, "scope": tc.scope},
				}, subordinateExtra)

				result, err := ResolveMetadataForEntityTypes(t.Context(), withAnchorKeysFrom(t, model.Configuration{}, chain), chainAnchor, chainAnchor, chain, nil, tc.entityTypes)
				if refused {
					if !errors.Is(err, model.ErrInvalidMetadata) {
						t.Fatalf("[6.1.4.2] expected an empty scope to be refused as invalid_metadata, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("expected the resolution to succeed, got %v", err)
				}
				if tc.expect == "" {
					return
				}
				body := map[string]any{}
				switch entityType {
				case "openid_relying_party":
					body = *result.Metadata.OpenIDRelyingPartyMetadata
				case "oauth_client":
					body = *result.Metadata.OAuthClientMetadata
				}
				if body["scope"] != tc.expect {
					t.Errorf("expected scope %q, got %#v", tc.expect, body["scope"])
				}
			})
		}
	}
}
