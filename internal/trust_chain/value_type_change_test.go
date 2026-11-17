package trust_chain

import (
	"errors"
	"reflect"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestResolveMetadata_ValueOfAnotherTypeIsAssignedAndThenVerified(t *testing.T) {
	tests := map[string]struct {
		parameter string
		value     any
		valid     bool
	}{
		"an array replaced by a string the entity type accepts": {parameter: "contacts", value: "admin@leaf.example.com", valid: true},
		"an endpoint set to a number the entity type refuses":   {parameter: "federation_fetch_endpoint", value: float64(42)},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain := chainWithClaims(t, nil, map[string]any{
				"metadata_policy": map[string]any{
					"federation_entity": map[string]any{tc.parameter: map[string]any{"value": tc.value}},
				},
			})

			result, err := resolveTrustingSuppliedAnchor(t, t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
			if !tc.valid {
				if !errors.Is(err, model.ErrInvalidMetadata) {
					t.Fatalf("[6.1] expected the resolved metadata to be refused as invalid_metadata, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[6.1.3.1.1] expected the operator value to be assigned, got %v", err)
			}
			if got := resolvedFederationParameter(t, result, tc.parameter); !reflect.DeepEqual(got, tc.value) {
				t.Errorf("[6.1.3.1.1] expected %#v, got %#v", tc.value, got)
			}
		})
	}
}
