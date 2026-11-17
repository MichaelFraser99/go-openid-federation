package trust_chain

import (
	"encoding/json"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_AnEmptySubsetOfIntersectionIsAnEmptyArray(t *testing.T) {
	chain := chainWithClaims(t, nil, map[string]any{
		"metadata_policy": map[string]any{
			"federation_entity": map[string]any{"contacts": map[string]any{"subset_of": []any{"other@ta.example.com"}}},
		},
	})

	result, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
	if err != nil {
		t.Fatalf("no error expected resolving, got: %v", err)
	}
	raw, err := json.Marshal(*result.Metadata.FederationMetadata)
	if err != nil {
		t.Fatalf("failed to marshal the metadata: %v", err)
	}
	if string(raw) != `{"contacts":[]}` {
		t.Errorf("[6.1.3.1.5] expected {\"contacts\":[]}, got %s", raw)
	}
}
