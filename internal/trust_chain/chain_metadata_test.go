package trust_chain

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_AppliesImmediateSuperiorMetadata(t *testing.T) {
	tests := []struct {
		name             string
		subjectMetadata  map[string]any
		subordinateExtra map[string]any
		expectContacts   []any
	}{
		{
			name: "a superior supplied parameter with no policy in the chain",
			subordinateExtra: map[string]any{
				"metadata": map[string]any{
					"federation_entity": map[string]any{"contacts": []any{"superior-set@ta.example.com"}},
				},
			},
			expectContacts: []any{"superior-set@ta.example.com"},
		},
		{
			name: "a superior supplied parameter applied before the policy",
			subordinateExtra: map[string]any{
				"metadata": map[string]any{
					"federation_entity": map[string]any{"contacts": []any{"superior-set@ta.example.com"}},
				},
				"metadata_policy": map[string]any{
					"federation_entity": map[string]any{"contacts": map[string]any{"add": []any{"ops@ta.example.com"}}},
				},
			},
			expectContacts: []any{"superior-set@ta.example.com", "ops@ta.example.com"},
		},
		{
			name: "a parameter the superior does not supply is left as the subject published it",
			subordinateExtra: map[string]any{
				"metadata": map[string]any{
					"federation_entity": map[string]any{"organization_name": "Pinned"},
				},
			},
			expectContacts: []any{"leaf@leaf.example.com"},
		},
		{
			name:           "no metadata claim in the subordinate statement",
			expectContacts: []any{"leaf@leaf.example.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainWithClaims(t, test.subjectMetadata, test.subordinateExtra)
			result, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain, nil)
			if err != nil {
				t.Fatalf("no error expected resolving, got: %v", err)
			}
			if got := resolvedFederationParameter(t, result, "contacts"); !reflect.DeepEqual(got, any(test.expectContacts)) {
				t.Errorf("expected contacts %v, got %v", test.expectContacts, got)
			}
		})
	}
}

func TestResolveMetadata_SuperiorMetadataOnlyAffectsTypesTheSubjectPublishes(t *testing.T) {
	chain := chainWithClaims(t, nil, map[string]any{
		"metadata": map[string]any{
			"federation_entity": map[string]any{"contacts": []any{"superior-set@ta.example.com"}},
			"oauth_resource":    map[string]any{"resource": "https://leaf.example.com/api"},
		},
	})

	result, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain, nil)
	if err != nil {
		t.Fatalf("no error expected resolving, got: %v", err)
	}
	if got := resolvedFederationParameter(t, result, "contacts"); !reflect.DeepEqual(got, any([]any{"superior-set@ta.example.com"})) {
		t.Errorf("expected the superior's parameter to be applied, got %v", got)
	}
	if result.Metadata.OAuthResourceMetadata != nil {
		t.Errorf("a superior must not add an entity type the subject does not publish, got %v", *result.Metadata.OAuthResourceMetadata)
	}
}

func TestResolveMetadata_PartialMetadataIsCompletedBeforeItIsJudged(t *testing.T) {
	tests := []struct {
		name             string
		subjectMetadata  map[string]any
		subordinateExtra map[string]any
		resolves         bool
	}{
		{
			name:            "a policy completes the subject's required parameter",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{"client_name": "Leaf RP"}},
			subordinateExtra: map[string]any{"metadata_policy": map[string]any{"openid_relying_party": map[string]any{
				"redirect_uris": map[string]any{"value": []any{"https://leaf.example.com/cb"}},
			}}},
			resolves: true,
		},
		{
			name:            "a superior supplies the subject's required parameter",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{"client_name": "Leaf RP"}},
			subordinateExtra: map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{
				"redirect_uris": []any{"https://leaf.example.com/cb"},
			}}},
			resolves: true,
		},
		{
			name: "a superior supplies selected parameters for a complete subject",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{
				"client_name":   "Leaf RP",
				"redirect_uris": []any{"https://leaf.example.com/cb"},
			}},
			subordinateExtra: map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{
				"contacts": []any{"ops@ta.example.com"},
			}}},
			resolves: true,
		},
		{
			name:            "nothing completes the required parameter and a policy applies",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{"client_name": "Leaf RP"}},
			subordinateExtra: map[string]any{"metadata_policy": map[string]any{"openid_relying_party": map[string]any{
				"contacts": map[string]any{"add": []any{"ops@ta.example.com"}},
			}}},
		},
		{
			name:            "nothing completes the required parameter and no policy applies",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{"client_name": "Leaf RP"}},
		},
		{
			name:            "an entity type declared as the empty object that nothing completes",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{}},
		},
		{
			name:            "an entity type declared as the empty object that a policy completes",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{}},
			subordinateExtra: map[string]any{"metadata_policy": map[string]any{"openid_relying_party": map[string]any{
				"redirect_uris": map[string]any{"value": []any{"https://leaf.example.com/cb"}},
			}}},
			resolves: true,
		},
		{
			name:            "a policy that removes the last parameter of a type",
			subjectMetadata: map[string]any{"openid_relying_party": map[string]any{"redirect_uris": []any{"https://leaf.example.com/cb"}}},
			subordinateExtra: map[string]any{"metadata_policy": map[string]any{"openid_relying_party": map[string]any{
				"redirect_uris": map[string]any{"value": nil},
			}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainWithClaims(t, test.subjectMetadata, test.subordinateExtra)
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain, nil)
			if test.resolves {
				if err != nil {
					t.Errorf("expected the chain to resolve, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Error("expected resolved metadata missing a required parameter to be rejected")
			}
		})
	}
}

func TestResolveMetadata_OnlyTheImmediateSuperiorSuppliesMetadata(t *testing.T) {
	tests := []struct {
		name             string
		immediateExtra   map[string]any
		grandparentExtra map[string]any
		expectContacts   []any
	}{
		{
			name: "the immediate superior supplies the parameter",
			immediateExtra: map[string]any{"metadata": map[string]any{
				"federation_entity": map[string]any{"contacts": []any{"from-intermediate@example.com"}},
			}},
			expectContacts: []any{"from-intermediate@example.com"},
		},
		{
			name: "a statement about the superior has no effect on the subject",
			grandparentExtra: map[string]any{"metadata": map[string]any{
				"federation_entity": map[string]any{"contacts": []any{"from-anchor@example.com"}},
			}},
			expectContacts: []any{"leaf@leaf.example.com"},
		},
		{
			name: "the immediate superior wins over a statement about it",
			immediateExtra: map[string]any{"metadata": map[string]any{
				"federation_entity": map[string]any{"contacts": []any{"from-intermediate@example.com"}},
			}},
			grandparentExtra: map[string]any{"metadata": map[string]any{
				"federation_entity": map[string]any{"contacts": []any{"from-anchor@example.com"}},
			}},
			expectContacts: []any{"from-intermediate@example.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainThroughIntermediate(t, test.immediateExtra, test.grandparentExtra)
			result, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain, nil)
			if err != nil {
				t.Fatalf("no error expected resolving, got: %v", err)
			}
			if got := resolvedFederationParameter(t, result, "contacts"); !reflect.DeepEqual(got, any(test.expectContacts)) {
				t.Errorf("expected contacts %v, got %v", test.expectContacts, got)
			}
		})
	}
}

func TestResolveMetadata_PolicyFromEveryLevelStillMerges(t *testing.T) {
	chain := chainThroughIntermediate(t,
		map[string]any{"metadata_policy": map[string]any{
			"federation_entity": map[string]any{"contacts": map[string]any{"add": []any{"from-intermediate@example.com"}}},
		}},
		map[string]any{"metadata_policy": map[string]any{
			"federation_entity": map[string]any{"contacts": map[string]any{"add": []any{"from-anchor@example.com"}}},
		}})

	result, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain, nil)
	if err != nil {
		t.Fatalf("no error expected resolving, got: %v", err)
	}

	got, ok := resolvedFederationParameter(t, result, "contacts").([]any)
	if !ok {
		t.Fatalf("expected an array of contacts, got %T", resolvedFederationParameter(t, result, "contacts"))
	}
	for _, want := range []any{"leaf@leaf.example.com", "from-intermediate@example.com", "from-anchor@example.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("expected the merged policy to contribute %v, got %v", want, got)
		}
	}
}

func TestResolveMetadata_SingleEntryChainIsJudgedOnItsOwnMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		resolves bool
	}{
		{
			name:     "a complete entity type",
			metadata: map[string]any{"openid_relying_party": map[string]any{"redirect_uris": []any{"https://ta.example.com/cb"}}},
			resolves: true,
		},
		{
			name:     "an entity type missing a required parameter",
			metadata: map[string]any{"openid_relying_party": map[string]any{"client_name": "Anchor RP"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainWithClaims(t, test.metadata, nil)
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain[:1], nil)
			if test.resolves {
				if err != nil {
					t.Errorf("expected the entity configuration to resolve, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Error("a chain of one has no superior to complete it, so it must be judged as it stands")
			}
		})
	}
}

func TestResolveMetadata_SuperiorCannotCreateAnInvalidCombination(t *testing.T) {
	chain := chainWithClaims(t,
		map[string]any{"openid_relying_party": map[string]any{
			"redirect_uris": []any{"https://leaf.example.com/cb"},
			"jwks":          map[string]any{"keys": []any{}},
		}},
		map[string]any{"metadata": map[string]any{"openid_relying_party": map[string]any{
			"jwks_uri": "https://ta.example.com/leaf/jwks",
		}}})

	if _, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain, nil); err == nil {
		t.Error("a superior must not be able to produce resolved metadata holding both key parameters")
	}
}

func TestResolveMetadata_MetadataFaultsOnASingleEntryChainAreTypedAsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
	}{
		{
			name:     "a claim of the wrong shape",
			metadata: map[string]any{"openid_relying_party": map[string]any{"redirect_uris": "not-an-array"}},
		},
		{
			name:     "a missing required claim",
			metadata: map[string]any{"openid_relying_party": map[string]any{"client_name": "Anchor RP"}},
		},
		{
			name:     "an entity type resolving to the empty object",
			metadata: map[string]any{"openid_relying_party": map[string]any{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := chainWithClaims(t, test.metadata, nil)
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chain[:1], nil)
			if err == nil {
				t.Fatal("expected the entity configuration to be refused")
			}
			if !errors.Is(err, model.ErrInvalidMetadata) {
				t.Errorf("a peer's metadata fault must be typed as invalid metadata, got %T: %v", err, err)
			}
		})
	}
}
