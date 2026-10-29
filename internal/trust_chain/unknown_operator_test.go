package trust_chain

import (
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_AnUnknownNonCriticalOperatorIsIgnored(t *testing.T) {
	subjectMetadata := map[string]any{
		"federation_entity": map[string]any{
			"organization_name": "Leaf Org",
			"contacts":          []any{"leaf@leaf.example.com"},
		},
	}

	tests := map[string]struct {
		subordinate  map[string]any
		expectErr    string
		expectName   string
		expectContac []any
	}{
		"an unknown operator beside a known one": {
			subordinate: map[string]any{"metadata_policy": map[string]any{"federation_entity": map[string]any{
				"organization_name": map[string]any{"regexp": "^Leaf"},
				"contacts":          map[string]any{"add": []any{"ops@ta.example.com"}, "regexp": ".*"},
			}}},
			expectName:   "Leaf Org",
			expectContac: []any{"leaf@leaf.example.com", "ops@ta.example.com"},
		},
		"only unknown operators on a parameter": {
			subordinate: map[string]any{"metadata_policy": map[string]any{"federation_entity": map[string]any{
				"organization_name": map[string]any{"regexp": "^Leaf", "https://example.com/op": true},
			}}},
			expectName:   "Leaf Org",
			expectContac: []any{"leaf@leaf.example.com"},
		},
		"an operator name in another case is not the known one": {
			subordinate: map[string]any{"metadata_policy": map[string]any{"federation_entity": map[string]any{
				"organization_name": map[string]any{"VALUE": "Overwritten"},
			}}},
			expectName:   "Leaf Org",
			expectContac: []any{"leaf@leaf.example.com"},
		},
		"the unknown operator listed as critical": {
			subordinate: map[string]any{
				"metadata_policy":      map[string]any{"federation_entity": map[string]any{"organization_name": map[string]any{"regexp": "^Leaf"}}},
				"metadata_policy_crit": []any{"regexp"},
			},
			expectErr: "'metadata_policy_crit' claim lists [regexp], none of which this implementation understands",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resolved, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chainWithClaims(t, subjectMetadata, tc.subordinate), nil)
			if tc.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("[6.1.3.2] an operator listed in metadata_policy_crit must be understood, so expected %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[6.1.3.2] implementations MUST ignore additional operators that are not understood, got %v", err)
			}
			if got := resolvedFederationParameter(t, resolved, "organization_name"); got != tc.expectName {
				t.Errorf("expected organization_name %q, got %v", tc.expectName, got)
			}
			got, _ := resolvedFederationParameter(t, resolved, "contacts").([]any)
			if len(got) != len(tc.expectContac) {
				t.Fatalf("expected contacts %v, got %v", tc.expectContac, got)
			}
			for i := range got {
				if got[i] != tc.expectContac[i] {
					t.Errorf("expected contacts %v, got %v", tc.expectContac, got)
				}
			}
		})
	}
}
