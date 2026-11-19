package trust_chain

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadataForEntityTypes_JudgesTheTypeOfAScopePerEntityType(t *testing.T) {
	tests := map[string]struct {
		scope  any
		policy map[string]any
	}{
		"a value that pins a number":                               {scope: "openid", policy: map[string]any{"value": 5}},
		"a default that supplies a boolean":                        {policy: map[string]any{"default": true}},
		"a value that pins an array holding a number":              {scope: "openid", policy: map[string]any{"value": []any{"openid", 5}}},
		"essential over a scope the subject publishes as an array": {scope: []any{"openid", "profile"}, policy: map[string]any{"essential": true}},
		"add over a scope the subject publishes as an array":       {scope: []any{"openid"}, policy: map[string]any{"add": []any{"profile"}}},
		"a subject that publishes a number":                        {scope: 5},
	}

	for _, entityType := range []string{"openid_relying_party", "oauth_client"} {
		for name, tc := range tests {
			body := map[string]any{"redirect_uris": []any{"https://leaf.example.com/cb"}}
			if tc.scope != nil {
				body["scope"] = tc.scope
			}
			subordinateExtra := map[string]any{"metadata_policy": map[string]any{entityType: map[string]any{"scope": tc.policy}}}
			if tc.policy == nil {
				subordinateExtra = nil
			}

			t.Run(entityType+", "+name+", the type not requested", func(t *testing.T) {
				chain := chainWithClaims(t, map[string]any{"federation_entity": map[string]any{"organization_name": "Leaf"}, entityType: body}, subordinateExtra)
				result, err := ResolveMetadataForEntityTypes(t.Context(), withAnchorKeysFrom(t, model.Configuration{}, chain), chainAnchor, chainAnchor, chain, nil, []string{"federation_entity"})
				if err != nil {
					t.Fatalf("[6.1.4.2] expected a scope that is not a string to be judged only with its own entity type, as #103 judges value's type, got %v", err)
				}
				if result.Metadata == nil || result.Metadata.FederationMetadata == nil {
					t.Fatal("expected the federation_entity metadata that was requested")
				}
			})

			t.Run(entityType+", "+name+", the type requested", func(t *testing.T) {
				chain := chainWithClaims(t, map[string]any{"federation_entity": map[string]any{"organization_name": "Leaf"}, entityType: body}, subordinateExtra)
				_, err := ResolveMetadataForEntityTypes(t.Context(), withAnchorKeysFrom(t, model.Configuration{}, chain), chainAnchor, chainAnchor, chain, nil, []string{entityType})
				if !errors.Is(err, model.ErrInvalidMetadata) {
					t.Fatalf("[RFC 7591 section 2] expected a resolved scope that is not a string to be refused as invalid_metadata, got %v", err)
				}
			})
		}
	}
}
