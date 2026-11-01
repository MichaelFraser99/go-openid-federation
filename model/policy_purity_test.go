package model

import (
	"encoding/json"
	"testing"
)

func encodedPolicy(t *testing.T, policy *MetadataPolicy) string {
	t.Helper()
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to encode the policy: %v", err)
	}
	return string(encoded)
}

func operatorOrder(policy *MetadataPolicy, parameter string) []string {
	var order []string
	for _, operator := range policy.OpenIDRelyingPartyMetadata[parameter].Metadata {
		order = append(order, operator.String())
	}
	return order
}

func TestProcessAndExtractPolicy_LeavesTheChainItWasGivenUnchanged(t *testing.T) {
	const (
		leaf         = EntityIdentifier("https://leaf.example.com")
		intermediate = EntityIdentifier("https://int.example.com")
		anchor       = EntityIdentifier("https://ta.example.com")
	)

	tests := map[string]struct {
		lower string
		upper string
	}{
		"both levels add to the same parameter": {
			lower: `{"openid_relying_party":{"contacts":{"add":["a@example.com"]}}}`,
			upper: `{"openid_relying_party":{"contacts":{"add":["b@example.com"]}}}`,
		},
		"only the upper level has the parameter": {
			lower: `{"openid_relying_party":{"client_name":{"value":"rp"}}}`,
			upper: `{"openid_relying_party":{"contacts":{"add":["b@example.com"]}}}`,
		},
		"only the lower level has the entity type": {
			lower: `{"openid_relying_party":{"contacts":{"add":["a@example.com"]}}}`,
			upper: `{"oauth_client":{"contacts":{"add":["b@example.com"]}}}`,
		},
		"the levels narrow the same subset_of": {
			lower: `{"openid_relying_party":{"scope":{"subset_of":["openid","profile","admin"]}}}`,
			upper: `{"openid_relying_party":{"scope":{"subset_of":["openid"]}}}`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			lower, upper := chainPolicy(t, tc.lower), chainPolicy(t, tc.upper)
			lowerBefore, upperBefore := encodedPolicy(t, lower), encodedPolicy(t, upper)
			chain := []EntityStatement{
				{Iss: leaf, Sub: leaf},
				{Iss: intermediate, Sub: leaf, MetadataPolicy: lower},
				{Iss: anchor, Sub: intermediate, MetadataPolicy: upper},
				{Iss: anchor, Sub: anchor},
			}

			first, err := ProcessAndExtractPolicy(chain)
			if err != nil {
				t.Fatalf("expected the policies to combine, got %v", err)
			}
			if got := encodedPolicy(t, lower); got != lowerBefore {
				t.Errorf("the lower statement's policy was changed from %s to %s", lowerBefore, got)
			}
			if got := encodedPolicy(t, upper); got != upperBefore {
				t.Errorf("the upper statement's policy was changed from %s to %s", upperBefore, got)
			}

			second, err := ProcessAndExtractPolicy(chain)
			if err != nil {
				t.Fatalf("expected the policies to combine a second time, got %v", err)
			}
			if encodedPolicy(t, first) != encodedPolicy(t, second) {
				t.Errorf("resolving the same chain twice gave %s and then %s", encodedPolicy(t, first), encodedPolicy(t, second))
			}
		})
	}
}

func TestProcessAndExtractPolicy_DoesNotReorderTheOperatorsItWasGiven(t *testing.T) {
	essential, err := NewEssential(true)
	if err != nil {
		t.Fatalf("failed to build the operator: %v", err)
	}
	fallback, err := NewDefault([]any{"d@example.com"})
	if err != nil {
		t.Fatalf("failed to build the operator: %v", err)
	}
	policy := &MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{
		"contacts": {Metadata: []MetadataPolicyOperator{*essential, *fallback, mustAdd(t, []any{"a@example.com"})}},
	}}
	before := operatorOrder(policy, "contacts")
	chain := []EntityStatement{
		{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com"},
		{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: policy},
		{Iss: "https://ta.example.com", Sub: "https://ta.example.com"},
	}

	if _, err := ProcessAndExtractPolicy(chain); err != nil {
		t.Fatalf("expected the policy to validate, got %v", err)
	}
	after := operatorOrder(policy, "contacts")
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("validating the policy reordered the caller's operators from %v to %v", before, after)
		}
	}
}

func TestApplyPolicy_LeavesTheStatementItWasGivenUnchanged(t *testing.T) {
	nested := map[string]any{"en": "Original"}
	rp := OpenIDRelyingPartyMetadata{
		"redirect_uris":     []any{"https://leaf.example.com/cb"},
		"organization_name": "Original",
		"contacts":          []any{"a@example.com"},
		"x_names":           nested,
	}
	subject := EntityStatement{Iss: "https://leaf.example.com", Sub: "https://leaf.example.com", Metadata: &Metadata{OpenIDRelyingPartyMetadata: &rp}}
	policy := chainPolicy(t, `{"openid_relying_party":{"organization_name":{"value":"Replaced"},"contacts":{"add":["b@example.com"]},"x_names":{"value":{"en":"Replaced"}},"redirect_uris":{"value":null}}}`)

	resolved, err := ApplyPolicy(subject, *policy)
	if err != nil {
		t.Fatalf("expected the policy to apply, got %v", err)
	}

	if (*resolved.Metadata.OpenIDRelyingPartyMetadata)["organization_name"] != "Replaced" {
		t.Fatalf("the fixture is wrong: the policy did not apply, got %v", *resolved.Metadata.OpenIDRelyingPartyMetadata)
	}
	if resolved.Metadata == subject.Metadata {
		t.Error("the returned statement shares the caller's Metadata")
	}
	if rp["organization_name"] != "Original" {
		t.Errorf("a value operator overwrote the caller's own map: organization_name is now %v", rp["organization_name"])
	}
	if contacts, _ := rp["contacts"].([]any); len(contacts) != 1 {
		t.Errorf("an add operator changed the caller's own array: contacts is now %v", rp["contacts"])
	}
	if _, present := rp["redirect_uris"]; !present {
		t.Error("a value of null removed the parameter from the caller's own map")
	}
	if nested["en"] != "Original" {
		t.Errorf("a value operator wrote into a nested object the caller holds: it is now %v", nested["en"])
	}
}

func TestMergePolicyOperators_DoesNotHandBackAnInputsOwnSlice(t *testing.T) {
	present := PolicyOperators{Metadata: []MetadataPolicyOperator{mustAdd(t, []any{"a"})}}

	for name, merge := range map[string]func() ([]MetadataPolicyOperator, error){
		"the first set empty":  func() ([]MetadataPolicyOperator, error) { return MergePolicyOperators("x", PolicyOperators{}, present) },
		"the second set empty": func() ([]MetadataPolicyOperator, error) { return MergePolicyOperators("x", present, PolicyOperators{}) },
	} {
		t.Run(name, func(t *testing.T) {
			merged, err := merge()
			if err != nil {
				t.Fatalf("expected the merge to succeed, got %v", err)
			}
			if len(merged) != 1 {
				t.Fatalf("expected the surviving set, got %v", merged)
			}
			if &merged[0] == &present.Metadata[0] {
				t.Error("the merged result shares the input's backing array")
			}
		})
	}
}

func TestProcessAndExtractPolicy_TheResultSharesNothingWithTheChain(t *testing.T) {
	const (
		leaf   = EntityIdentifier("https://leaf.example.com")
		lowest = EntityIdentifier("https://int1.example.com")
		middle = EntityIdentifier("https://int2.example.com")
		anchor = EntityIdentifier("https://ta.example.com")
	)
	policies := []*MetadataPolicy{
		chainPolicy(t, `{"openid_relying_party":{"contacts":{"add":["a@example.com"]}}}`),
		chainPolicy(t, `{"openid_relying_party":{"client_name":{"value":"rp","x_unknown":1}},"oauth_client":{"contacts":{"add":["b@example.com"]}}}`),
		chainPolicy(t, `{"oauth_client":{"contacts":{"add":["c@example.com"]}}}`),
	}
	before := make([]string, len(policies))
	for i, policy := range policies {
		before[i] = encodedPolicy(t, policy)
	}
	unrecognised := policies[1].OpenIDRelyingPartyMetadata["client_name"].Unrecognised
	if len(unrecognised) != 1 || unrecognised[0] != "x_unknown" {
		t.Fatalf("the fixture is wrong: expected one unrecognised operator, got %v", unrecognised)
	}
	chain := []EntityStatement{
		{Iss: leaf, Sub: leaf},
		{Iss: lowest, Sub: leaf, MetadataPolicy: policies[0]},
		{Iss: middle, Sub: lowest, MetadataPolicy: policies[1]},
		{Iss: anchor, Sub: middle, MetadataPolicy: policies[2]},
		{Iss: anchor, Sub: anchor},
	}

	resolved, err := ProcessAndExtractPolicy(chain)
	if err != nil {
		t.Fatalf("expected the policies to combine, got %v", err)
	}
	for i, policy := range policies {
		if got := encodedPolicy(t, policy); got != before[i] {
			t.Errorf("level %d's policy was changed by the merge from %s to %s", i, before[i], got)
		}
	}

	replacement := mustAdd(t, []any{"z@example.com"})
	for _, parameters := range resolved.byEntityType() {
		for parameter, operators := range parameters {
			for i := range operators.Metadata {
				operators.Metadata[i] = replacement
			}
			for i := range operators.Unrecognised {
				operators.Unrecognised[i] = "x_overwritten"
			}
			parameters[parameter] = PolicyOperators{}
		}
	}
	for i, policy := range policies {
		if got := encodedPolicy(t, policy); got != before[i] {
			t.Errorf("writing into the result reached level %d's policy: it changed from %s to %s", i, before[i], got)
		}
	}
	if unrecognised[0] != "x_unknown" {
		t.Errorf("writing into the result reached level 1's unrecognised operators: it is now %v", unrecognised)
	}
}
