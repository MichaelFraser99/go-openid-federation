package trust_chain

import (
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func constraintsClaim(members map[string]any) map[string]any {
	return map[string]any{"constraints": members}
}

func TestResolveMetadata_EnforcesMaxPathLength(t *testing.T) {
	tests := map[string]struct {
		immediate   map[string]any
		grandparent map[string]any
		expectErr   string
	}{
		"no constraint":                             {},
		"the anchor allows one intermediate":        {grandparent: constraintsClaim(map[string]any{"max_path_length": 1})},
		"the anchor allows none, and there is one":  {grandparent: constraintsClaim(map[string]any{"max_path_length": 0}), expectErr: "allows at most 0 intermediates below it, and the trust chain has 1"},
		"the intermediate allows none about a leaf": {immediate: constraintsClaim(map[string]any{"max_path_length": 0})},
		"both set, each independently satisfied":    {immediate: constraintsClaim(map[string]any{"max_path_length": 0}), grandparent: constraintsClaim(map[string]any{"max_path_length": 1})},
		"unknown members are ignored":               {grandparent: constraintsClaim(map[string]any{"https://example.com/extension": true})},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chainThroughIntermediate(t, tc.immediate, tc.grandparent), nil)
			assertConstraintVerdict(t, "6.2.1", err, tc.expectErr)
		})
	}
}

func TestResolveMetadata_EnforcesNamingConstraints(t *testing.T) {
	naming := func(members map[string]any) map[string]any {
		return constraintsClaim(map[string]any{"naming_constraints": members})
	}

	tests := map[string]struct {
		immediate   map[string]any
		grandparent map[string]any
		expectErr   string
	}{
		"a domain covering every subordinate":             {grandparent: naming(map[string]any{"permitted": []any{".example.com"}})},
		"a domain does not cover its own apex":            {grandparent: naming(map[string]any{"permitted": []any{".leaf.example.com", ".intermediate.example.com"}}), expectErr: "https://leaf.example.com is outside the naming constraints"},
		"a host permits only that host":                   {grandparent: naming(map[string]any{"permitted": []any{"leaf.example.com"}}), expectErr: "https://intermediate.example.com is outside the naming constraints"},
		"a host does not cover its subdomains":            {grandparent: naming(map[string]any{"permitted": []any{"example.com"}}), expectErr: "is outside the naming constraints"},
		"two hosts permit both subordinates":              {grandparent: naming(map[string]any{"permitted": []any{"leaf.example.com", "intermediate.example.com"}})},
		"an excluded intermediate":                        {grandparent: naming(map[string]any{"excluded": []any{"intermediate.example.com"}}), expectErr: "https://intermediate.example.com is outside the naming constraints"},
		"an excluded subject":                             {grandparent: naming(map[string]any{"excluded": []any{"leaf.example.com"}}), expectErr: "https://leaf.example.com is outside the naming constraints"},
		"an exclusion wins over a permission":             {grandparent: naming(map[string]any{"permitted": []any{".example.com"}, "excluded": []any{"leaf.example.com"}}), expectErr: "https://leaf.example.com is outside the naming constraints"},
		"an exclusion matches whatever its case":          {grandparent: naming(map[string]any{"excluded": []any{"LEAF.Example.COM"}}), expectErr: "https://leaf.example.com is outside the naming constraints"},
		"an exclusion matches with a trailing dot":        {grandparent: naming(map[string]any{"excluded": []any{"leaf.example.com."}}), expectErr: "https://leaf.example.com is outside the naming constraints"},
		"an empty permitted list is refused as malformed": {grandparent: naming(map[string]any{"permitted": []any{}}), expectErr: "'permitted' must not be empty"},
		"an empty excluded list excludes nothing":         {grandparent: naming(map[string]any{"excluded": []any{}})},
		"an exclusion elsewhere permits everything here":  {grandparent: naming(map[string]any{"excluded": []any{".other.org"}})},
		"the anchor itself is not a subordinate":          {grandparent: naming(map[string]any{"excluded": []any{"ta.example.com"}})},
		"a constraint covers only the entities below it":  {immediate: naming(map[string]any{"permitted": []any{"leaf.example.com"}})},
		"each constraint is applied independently":        {immediate: naming(map[string]any{"permitted": []any{"leaf.example.com"}}), grandparent: naming(map[string]any{"excluded": []any{"leaf.example.com"}}), expectErr: "https://leaf.example.com is outside the naming constraints set by https://ta.example.com"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chainThroughIntermediate(t, tc.immediate, tc.grandparent), nil)
			assertConstraintVerdict(t, "6.2.2", err, tc.expectErr)
		})
	}
}

func TestResolveMetadata_EnforcesAllowedEntityTypes(t *testing.T) {
	subjectMetadata := func() map[string]any {
		return map[string]any{
			"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}},
			"custom_kept":       map[string]any{"a": "b"},
			"custom_removed":    map[string]any{"a": "b"},
		}
	}

	tests := map[string]struct {
		subordinate map[string]any
		expectTypes []string
	}{
		"no constraint keeps every type": {
			expectTypes: []string{"custom_kept", "custom_removed"},
		},
		"other constraints leave every type": {
			subordinate: constraintsClaim(map[string]any{"max_path_length": 0}),
			expectTypes: []string{"custom_kept", "custom_removed"},
		},
		"an empty list keeps only federation_entity": {
			subordinate: constraintsClaim(map[string]any{"allowed_entity_types": []any{}}),
		},
		"a listed type is kept and the rest removed": {
			subordinate: constraintsClaim(map[string]any{"allowed_entity_types": []any{"custom_kept"}}),
			expectTypes: []string{"custom_kept"},
		},
		"a type the subject does not have is not added": {
			subordinate: constraintsClaim(map[string]any{"allowed_entity_types": []any{"custom_kept", "openid_provider"}}),
			expectTypes: []string{"custom_kept"},
		},
		"removal precedes the metadata policy": {
			subordinate: map[string]any{
				"metadata_policy": map[string]any{"custom_removed": map[string]any{"required": map[string]any{"essential": true}}},
				"constraints":     map[string]any{"allowed_entity_types": []any{"custom_kept"}},
			},
			expectTypes: []string{"custom_kept"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resolved, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chainWithClaims(t, subjectMetadata(), tc.subordinate), nil)
			if err != nil {
				t.Fatalf("[6.2.3] expected the chain to resolve, got %v", err)
			}
			if resolved.Metadata.FederationMetadata == nil {
				t.Errorf("[6.2.3] federation_entity must never be removed")
			}
			for _, entityType := range []string{"custom_kept", "custom_removed"} {
				_, present := resolved.Metadata.Extensions[entityType]
				expected := false
				for _, kept := range tc.expectTypes {
					expected = expected || kept == entityType
				}
				if present != expected {
					t.Errorf("[6.2.3] expected %s present %v, got %v", entityType, expected, present)
				}
			}
			if _, present := resolved.Metadata.Extensions["openid_provider"]; present || resolved.Metadata.OpenIDConnectOpenIDProviderMetadata != nil {
				t.Errorf("[6.2.3] an allowed type the subject never had must not appear")
			}
		})
	}
}

func TestResolveMetadata_AllowedEntityTypesAtEveryLevelApply(t *testing.T) {
	tests := map[string]struct {
		immediate   map[string]any
		grandparent map[string]any
	}{
		"set by the immediate superior": {immediate: constraintsClaim(map[string]any{"allowed_entity_types": []any{}})},
		"set by the trust anchor":       {grandparent: constraintsClaim(map[string]any{"allowed_entity_types": []any{}})},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain := chainThroughIntermediateWithMetadata(t, map[string]any{
				"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}},
				"custom_removed":    map[string]any{"a": "b"},
			}, tc.immediate, tc.grandparent)
			resolved, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
			if err != nil {
				t.Fatalf("[6.2] expected the chain to resolve, got %v", err)
			}
			if _, present := resolved.Metadata.Extensions["custom_removed"]; present {
				t.Errorf("[6.2] the constraints claim in each subordinate statement must be applied")
			}
		})
	}
}

func assertConstraintVerdict(t *testing.T, reference string, err error, expectErr string) {
	t.Helper()
	if expectErr == "" {
		if err != nil {
			t.Fatalf("[%s] expected the chain to resolve, got %v", reference, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), expectErr) {
		t.Fatalf("[%s] expected a refusal containing %q, got %v", reference, expectErr, err)
	}
	if !errors.Is(err, model.ErrInvalidTrustChain) {
		t.Errorf("[%s] a chain failing its constraints is an invalid trust chain, got %v", reference, err)
	}
}

func chainThroughTwoIntermediates(t *testing.T, aboutLeaf, aboutI1, aboutI2 map[string]any) []string {
	t.Helper()
	const (
		i1 = model.EntityIdentifier("https://i1.example.com")
		i2 = model.EntityIdentifier("https://i2.example.com")
	)
	leafKey, i1Key, i2Key, anchorKey := chainSigningKey(t), chainSigningKey(t), chainSigningKey(t), chainSigningKey(t)
	now := time.Now().UTC()
	statement := func(iss, sub model.EntityIdentifier, keyOf *rsa.PrivateKey, extra map[string]any) map[string]any {
		body := map[string]any{"iss": string(iss), "sub": string(sub), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": chainJwks(t, keyOf)}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	leaf := statement(chainSubject, chainSubject, leafKey, map[string]any{
		"authority_hints": []any{string(i1)},
		"metadata":        map[string]any{"federation_entity": map[string]any{"contacts": []any{"leaf@leaf.example.com"}}},
	})
	anchor := statement(chainAnchor, chainAnchor, anchorKey, map[string]any{
		"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": string(chainAnchor) + "/fetch"}},
	})
	return []string{
		chainSignStatement(t, leafKey, leaf),
		chainSignStatement(t, i1Key, statement(i1, chainSubject, leafKey, aboutLeaf)),
		chainSignStatement(t, i2Key, statement(i2, i1, i1Key, aboutI1)),
		chainSignStatement(t, anchorKey, statement(chainAnchor, i2, i2Key, aboutI2)),
		chainSignStatement(t, anchorKey, anchor),
	}
}

func TestResolveMetadata_MaxPathLengthFollowsTheSpecificationsExamples(t *testing.T) {
	limit := func(n int) map[string]any { return constraintsClaim(map[string]any{"max_path_length": n}) }

	tests := map[string]struct {
		byI1, byI2, byTA map[string]any
		expectErr        string
	}{
		"the TA sets 2":                      {byTA: limit(2)},
		"the TA sets 2, I2 sets 1, I1 omits": {byTA: limit(2), byI2: limit(1)},
		"only I1 sets 0":                     {byI1: limit(0)},
		"the TA sets 1":                      {byTA: limit(1), expectErr: "allows at most 1 intermediates below it, and the trust chain has 2"},
		"I2 sets 0, with I1 below it":        {byI2: limit(0), expectErr: "allows at most 0 intermediates below it, and the trust chain has 1"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain := chainThroughTwoIntermediates(t, tc.byI1, tc.byI2, tc.byTA)
			_, err := ResolveMetadata(t.Context(), model.Configuration{}, chainAnchor, chainAnchor, chain, nil)
			assertConstraintVerdict(t, "6.2.1", err, tc.expectErr)
		})
	}
}
