package model

import (
	"encoding/json"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

func marshalled(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal %v: %v", value, err)
	}
	return string(raw)
}

func writeIntoResolved(resolved any) {
	switch typed := resolved.(type) {
	case map[string]any:
		typed["written"] = true
		if keys, ok := typed["keys"].([]any); ok && len(keys) > 0 {
			keys[0].(map[string]any)["kid"] = "written"
		}
	case []any:
		if len(typed) > 0 {
			if member, ok := typed[0].(map[string]any); ok {
				member["kid"] = "written"
				return
			}
			typed[0] = "written"
		}
	}
}

func TestResolve_HandsOutACopyOfTheOperand(t *testing.T) {
	keySet := func() map[string]any {
		return map[string]any{"keys": []any{map[string]any{"kty": "EC", "kid": "pinned"}}}
	}

	tests := []struct {
		name     string
		build    func(*testing.T) MetadataPolicyOperator
		metadata any
	}{
		{name: "value", build: func(t *testing.T) MetadataPolicyOperator {
			o, err := NewValue(keySet())
			if err != nil {
				t.Fatal(err)
			}
			return *o
		}},
		{name: "default over an absent parameter", build: func(t *testing.T) MetadataPolicyOperator {
			o, err := NewDefault(keySet())
			if err != nil {
				t.Fatal(err)
			}
			return *o
		}},
		{name: "add over an absent parameter", build: func(t *testing.T) MetadataPolicyOperator {
			o, err := NewAdd([]any{"ops@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			return *o
		}},
		{name: "add of objects over a present parameter", build: func(t *testing.T) MetadataPolicyOperator {
			o, err := NewAdd([]any{map[string]any{"kid": "pinned"}})
			if err != nil {
				t.Fatal(err)
			}
			return *o
		}, metadata: []any{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			operator := tc.build(t)
			before := marshalled(t, operator.OperatorValue())

			resolved, err := operator.Resolve(tc.metadata)
			if err != nil {
				t.Fatalf("expected the operator to resolve, got %v", err)
			}
			writeIntoResolved(resolved)

			if after := marshalled(t, operator.OperatorValue()); after != before {
				t.Errorf("[#156] a write to what Resolve returned reached the operator: want %s, got %s", before, after)
			}
		})
	}
}

func TestMergePolicyOperators_ASingleSidedResultSharesNoOperandWithItsInput(t *testing.T) {
	added, err := NewAdd([]any{map[string]any{"kid": "pinned"}})
	if err != nil {
		t.Fatal(err)
	}
	present := PolicyOperators{Metadata: []MetadataPolicyOperator{*added}}
	before := marshalled(t, added.OperatorValue())

	for name, merge := range map[string]func() ([]MetadataPolicyOperator, error){
		"the first set empty":  func() ([]MetadataPolicyOperator, error) { return MergePolicyOperators("x", PolicyOperators{}, present) },
		"the second set empty": func() ([]MetadataPolicyOperator, error) { return MergePolicyOperators("x", present, PolicyOperators{}) },
	} {
		t.Run(name, func(t *testing.T) {
			merged, err := merge()
			if err != nil {
				t.Fatalf("expected the merge to succeed, got %v", err)
			}
			held, ok := merged[0].(Add)
			if !ok {
				t.Fatalf("expected an add operator, got %T", merged[0])
			}
			held.operatorValue[0].(map[string]any)["kid"] = "written"

			if after := marshalled(t, added.OperatorValue()); after != before {
				t.Errorf("[#156] the merged operator shares its operand with the input: want %s, got %s", before, after)
			}
		})
	}
}

func fullStatement() EntityStatement {
	endpoint := "https://ta.example.com/fetch"
	pathLength := 1
	return EntityStatement{
		Iss:              "https://leaf.example.com",
		Sub:              "https://leaf.example.com",
		JWKs:             josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "kid": "own"}}},
		AuthorityHints:   []EntityIdentifier{"https://ta.example.com"},
		TrustAnchorHints: []EntityIdentifier{"https://ta.example.com"},
		Metadata:         &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"contacts": []any{"leaf@example.com"}}},
		MetadataPolicy:   &MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"contacts": {Metadata: []MetadataPolicyOperator{Add{operatorValue: []any{"x@example.com"}}}}}},
		Constraints:      &Constraints{MaxPathLength: &pathLength, AllowedEntityTypes: []string{"openid_relying_party"}, NamingConstraints: &NamingConstraints{Permitted: []string{"example.com"}}},
		TrustMarks:       []TrustMarkHolder{{TrustMarkType: "https://tm.example.com", TrustMark: "mark"}},
		TrustMarkIssuers: map[string][]EntityIdentifier{"https://tm.example.com": {"https://issuer.example.com"}},
		TrustMarkOwners:  map[string]TrustMarkOwner{"https://tm.example.com": {Sub: "https://owner.example.com", JWKs: josemodel.Jwks{Keys: []map[string]any{{"kty": "EC", "kid": "owner"}}}, AdditionalClaims: map[string]any{"x": []any{"y"}}}},
		SourceEndpoint:   &endpoint,
	}
}

func writeIntoStatement(statement *EntityStatement) {
	statement.JWKs.Keys[0]["kid"] = "written"
	statement.AuthorityHints[0] = "https://written.example.com"
	statement.TrustAnchorHints[0] = "https://written.example.com"
	if statement.Metadata != nil && statement.Metadata.OpenIDRelyingPartyMetadata != nil {
		(*statement.Metadata.OpenIDRelyingPartyMetadata)["contacts"].([]any)[0] = "written"
	}
	statement.MetadataPolicy.OpenIDRelyingPartyMetadata["contacts"] = PolicyOperators{}
	*statement.Constraints.MaxPathLength = 9
	statement.Constraints.AllowedEntityTypes[0] = "written"
	statement.Constraints.NamingConstraints.Permitted[0] = "written.example.com"
	statement.TrustMarks[0].TrustMark = "written"
	statement.TrustMarkIssuers["https://tm.example.com"][0] = "https://written.example.com"
	statement.TrustMarkOwners["https://tm.example.com"].JWKs.Keys[0]["kid"] = "written"
	statement.TrustMarkOwners["https://tm.example.com"].AdditionalClaims["x"].([]any)[0] = "written"
	*statement.SourceEndpoint = "https://written.example.com"
}

func statementSnapshot(t *testing.T, statement EntityStatement) string {
	t.Helper()
	return marshalled(t, []any{
		statement.JWKs, statement.AuthorityHints, statement.TrustAnchorHints, statement.Metadata, statement.MetadataPolicy,
		statement.Constraints, statement.TrustMarks, statement.TrustMarkIssuers, statement.TrustMarkOwners,
		statement.TrustMarkOwners["https://tm.example.com"].AdditionalClaims, statement.SourceEndpoint,
	})
}

func TestApplyPolicy_TheResultSharesNothingWithTheSubject(t *testing.T) {
	tests := map[string]func(*EntityStatement){
		"a subject with metadata":    func(*EntityStatement) {},
		"a subject with no metadata": func(statement *EntityStatement) { statement.Metadata = nil },
	}

	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			subject := fullStatement()
			change(&subject)
			before := statementSnapshot(t, subject)

			resolved, err := ApplyPolicy(subject, MetadataPolicy{})
			if err != nil {
				t.Fatalf("expected the policy to apply, got %v", err)
			}
			writeIntoStatement(resolved)

			if after := statementSnapshot(t, subject); after != before {
				t.Errorf("[#156] a write to what ApplyPolicy returned reached the subject:\nwant %s\ngot  %s", before, after)
			}
		})
	}
}

func TestApplySuperiorMetadata_TheResultSharesNothingWithEitherInput(t *testing.T) {
	subject := &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"contacts": []any{"leaf@example.com"}}}
	superior := &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"jwks": map[string]any{"keys": []any{map[string]any{"kty": "EC", "kid": "pinned"}}}}}
	before := marshalled(t, []any{subject, superior})

	merged := ApplySuperiorMetadata(subject, superior)
	writeIntoResolved((*merged.OpenIDRelyingPartyMetadata)["contacts"])
	writeIntoResolved((*merged.OpenIDRelyingPartyMetadata)["jwks"])

	if after := marshalled(t, []any{subject, superior}); after != before {
		t.Errorf("[#156] a write to what ApplySuperiorMetadata returned reached an input:\nwant %s\ngot  %s", before, after)
	}
}
