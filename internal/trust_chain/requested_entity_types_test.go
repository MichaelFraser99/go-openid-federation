package trust_chain

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadataForEntityTypes_JudgesOnlyTheTypesRequested(t *testing.T) {
	subjectMetadata := map[string]any{
		"federation_entity":    map[string]any{"organization_name": "Leaf"},
		"openid_relying_party": map[string]any{"client_name": "Leaf RP"},
	}
	paths := map[string]struct {
		subordinateExtra map[string]any
		singleEntry      bool
	}{
		"a single entry chain":   {singleEntry: true},
		"a chain with no policy": {},
		"a chain with a policy": {subordinateExtra: map[string]any{"metadata_policy": map[string]any{
			"federation_entity": map[string]any{"organization_name": map[string]any{"value": "Leaf"}},
		}}},
	}
	requests := map[string]struct {
		entityTypes []string
		refused     bool
		returned    bool
	}{
		"no entity type, so every type is requested": {refused: true},
		"only the broken type":                       {entityTypes: []string{"openid_relying_party"}, refused: true},
		"the broken type among others":               {entityTypes: []string{"federation_entity", "openid_relying_party"}, refused: true},
		"only a complete type":                       {entityTypes: []string{"federation_entity"}, returned: true},
		"only a type the subject does not publish":   {entityTypes: []string{"oauth_client"}},
	}

	for pathName, path := range paths {
		for requestName, request := range requests {
			t.Run(pathName+", "+requestName, func(t *testing.T) {
				chain := chainWithClaims(t, subjectMetadata, path.subordinateExtra)
				anchor := chainAnchor
				if path.singleEntry {
					chain = chain[:1]
					anchor = chainSubject
				}

				result, err := ResolveMetadataForEntityTypes(t.Context(), withAnchorKeysFrom(t, model.Configuration{}, chain), chainAnchor, anchor, chain, nil, request.entityTypes)
				if request.refused {
					if !errors.Is(err, model.ErrInvalidMetadata) {
						t.Fatalf("[6.1.4.2] expected a requested type that is broken to refuse the resolution, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("[6.1.4.2] expected a type that was not requested not to decide the answer, got %v", err)
				}
				if result.Metadata == nil {
					t.Fatal("expected metadata in the result")
				}
				if result.Metadata.OpenIDRelyingPartyMetadata != nil {
					t.Errorf("[6.1.4.2] the broken type MUST NOT be used, got %v", *result.Metadata.OpenIDRelyingPartyMetadata)
				}
				if returned := result.Metadata.FederationMetadata != nil; returned != request.returned {
					t.Errorf("[8.3.1] expected federation_entity returned=%v, got %v", request.returned, returned)
				}
			})
		}
	}
}

func TestResolveMetadataForEntityTypes_APolicyErrorOnAnUnrequestedTypeStillRefusesTheChain(t *testing.T) {
	chain := chainWithClaims(t, map[string]any{
		"federation_entity":    map[string]any{"organization_name": "Leaf"},
		"openid_relying_party": map[string]any{"client_name": "Leaf RP", "redirect_uris": []any{"https://leaf.example.com/cb"}},
	}, map[string]any{"metadata_policy": map[string]any{
		"openid_relying_party": map[string]any{"client_name": map[string]any{"one_of": []any{"Another RP"}}},
	}})

	_, err := ResolveMetadataForEntityTypes(t.Context(), withAnchorKeysFrom(t, model.Configuration{}, chain), chainAnchor, chainAnchor, chain, nil, []string{"federation_entity"})
	if err == nil {
		t.Fatal("[6.1.4] a policy error makes the trust chain invalid, whichever type was requested")
	}
}
