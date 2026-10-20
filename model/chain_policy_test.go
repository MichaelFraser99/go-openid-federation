package model

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

func chainPolicy(t *testing.T, raw string) *MetadataPolicy {
	t.Helper()
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatalf("no error expected parsing the policy, got: %v", err)
	}
	return &policy
}

func TestProcessAndExtractPolicy_TakesPolicyOnlyFromSubordinateStatements(t *testing.T) {
	const (
		leaf         = EntityIdentifier("https://leaf.example.com")
		intermediate = EntityIdentifier("https://int.example.com")
		anchor       = EntityIdentifier("https://ta.example.com")
	)

	configurationPolicy := `{"openid_relying_party":{"client_name":{"value":"from-a-configuration"}}}`
	superiorPolicy := `{"openid_relying_party":{"client_name":{"value":"from-the-superior"}}}`

	tests := []struct {
		name   string
		chain  func(*testing.T) []EntityStatement
		expect any
	}{
		{
			name: "a policy in the subject's own entity configuration",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{Iss: leaf, Sub: leaf, MetadataPolicy: chainPolicy(t, configurationPolicy)},
					{Iss: anchor, Sub: leaf},
					{Iss: anchor, Sub: anchor},
				}
			},
		},
		{
			name: "a policy in the trust anchor's entity configuration",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{Iss: leaf, Sub: leaf},
					{Iss: anchor, Sub: leaf},
					{Iss: anchor, Sub: anchor, MetadataPolicy: chainPolicy(t, configurationPolicy)},
				}
			},
		},
		{
			name: "a policy in the subordinate statement between them",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{Iss: leaf, Sub: leaf},
					{Iss: anchor, Sub: leaf, MetadataPolicy: chainPolicy(t, superiorPolicy)},
					{Iss: anchor, Sub: anchor},
				}
			},
			expect: "from-the-superior",
		},
		{
			name: "a policy at every level keeps only the subordinate statement's",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{Iss: leaf, Sub: leaf, MetadataPolicy: chainPolicy(t, configurationPolicy)},
					{Iss: anchor, Sub: leaf, MetadataPolicy: chainPolicy(t, superiorPolicy)},
					{Iss: anchor, Sub: anchor, MetadataPolicy: chainPolicy(t, configurationPolicy)},
				}
			},
			expect: "from-the-superior",
		},
		{
			name: "the trust anchor's own policy when its entity configuration is omitted",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{Iss: leaf, Sub: leaf},
					{Iss: intermediate, Sub: leaf},
					{Iss: anchor, Sub: intermediate, MetadataPolicy: chainPolicy(t, superiorPolicy)},
				}
			},
			expect: "from-the-superior",
		},
		{
			name: "a chain holding only entity configurations",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{Iss: leaf, Sub: leaf, MetadataPolicy: chainPolicy(t, configurationPolicy)},
					{Iss: anchor, Sub: anchor, MetadataPolicy: chainPolicy(t, configurationPolicy)},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := ProcessAndExtractPolicy(test.chain(t))
			if err != nil {
				t.Fatalf("no error expected extracting the policy, got: %v", err)
			}
			if test.expect == nil {
				if policy != nil && len(policy.OpenIDRelyingPartyMetadata) > 0 {
					t.Fatalf("expected no policy, got %+v", policy.OpenIDRelyingPartyMetadata)
				}
				return
			}
			if policy == nil {
				t.Fatal("expected the subordinate statement's policy to be extracted, got none")
			}
			operators, found := policy.OpenIDRelyingPartyMetadata["client_name"]
			if !found {
				t.Fatalf("expected a client_name policy, got %+v", policy.OpenIDRelyingPartyMetadata)
			}
			if got := operators.Metadata[0].OperatorValue(); !reflect.DeepEqual(got, test.expect) {
				t.Errorf("expected %v, got %v", test.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_MergesEverySubordinateStatementWhateverTheChainShape(t *testing.T) {
	const (
		leaf         = EntityIdentifier("https://leaf.example.com")
		intermediate = EntityIdentifier("https://int.example.com")
		anchor       = EntityIdentifier("https://ta.example.com")
	)

	build := func(t *testing.T, withAnchorConfiguration bool) []EntityStatement {
		t.Helper()
		chain := []EntityStatement{
			{Iss: leaf, Sub: leaf},
			{Iss: intermediate, Sub: leaf, MetadataPolicy: chainPolicy(t, `{"federation_entity":{"contacts":{"add":["int@example.com"]}}}`)},
			{Iss: anchor, Sub: intermediate, MetadataPolicy: chainPolicy(t, `{"federation_entity":{"contacts":{"add":["ta@example.com"]}}}`)},
		}
		if withAnchorConfiguration {
			chain = append(chain, EntityStatement{Iss: anchor, Sub: anchor})
		}
		return chain
	}

	for name, withAnchorConfiguration := range map[string]bool{
		"the trust anchor's entity configuration present": true,
		"the trust anchor's entity configuration omitted": false,
	} {
		t.Run(name, func(t *testing.T) {
			policy, err := ProcessAndExtractPolicy(build(t, withAnchorConfiguration))
			if err != nil {
				t.Fatalf("no error expected extracting the policy, got: %v", err)
			}
			if policy == nil {
				t.Fatal("expected a policy, got none")
			}
			operators, found := policy.FederationMetadata["contacts"]
			if !found {
				t.Fatalf("expected a contacts policy, got %+v", policy.FederationMetadata)
			}
			operands, ok := operators.Metadata[0].OperatorValue().([]any)
			if !ok {
				t.Fatalf("expected an array operand, got %T", operators.Metadata[0].OperatorValue())
			}
			for _, want := range []any{"int@example.com", "ta@example.com"} {
				if !slices.Contains(operands, want) {
					t.Errorf("expected every subordinate statement to contribute, %v missing from %v", want, operands)
				}
			}
		})
	}
}

func TestProcessAndExtractPolicy_RejectsAnEmptyChain(t *testing.T) {
	if got, err := ProcessAndExtractPolicy(nil); err == nil {
		t.Errorf("expected an empty chain to be refused, got %+v", got)
	}
}

func TestApplySuperiorMetadata(t *testing.T) {
	tests := []struct {
		name     string
		subject  *Metadata
		superior *Metadata
		expect   map[string]map[string]any
	}{
		{
			name:     "a parameter the subject also publishes is overridden",
			subject:  &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			superior: &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"superior@example.com"}}},
			expect:   map[string]map[string]any{"federation_entity": {"contacts": []any{"superior@example.com"}}},
		},
		{
			name:     "a parameter the subject does not publish is added",
			subject:  &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			superior: &Metadata{FederationMetadata: &FederationMetadata{"organization_name": "Pinned"}},
			expect: map[string]map[string]any{"federation_entity": {
				"contacts":          []any{"leaf@example.com"},
				"organization_name": "Pinned",
			}},
		},
		{
			name:     "an entity type the subject does not publish is ignored",
			subject:  &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			superior: &Metadata{OAuthResourceMetadata: &OAuthResourceMetadata{"resource": "https://leaf.example.com/api"}},
			expect:   map[string]map[string]any{"federation_entity": {"contacts": []any{"leaf@example.com"}}},
		},
		{
			name:    "no superior metadata leaves the subject as published",
			subject: &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			expect:  map[string]map[string]any{"federation_entity": {"contacts": []any{"leaf@example.com"}}},
		},
		{
			name:     "an extension entity type is overridden the same way",
			subject:  &Metadata{Extensions: map[string]map[string]any{"example_type": {"a": "subject"}}},
			superior: &Metadata{Extensions: map[string]map[string]any{"example_type": {"a": "superior"}}},
			expect:   map[string]map[string]any{"example_type": {"a": "superior"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subjectBefore := test.subject.byEntityType()
			snapshot, err := json.Marshal(subjectBefore)
			if err != nil {
				t.Fatalf("no error expected capturing the subject, got: %v", err)
			}

			got := ApplySuperiorMetadata(test.subject, test.superior)
			if got == nil {
				t.Fatal("expected metadata, got nil")
			}
			if !reflect.DeepEqual(got.byEntityType(), test.expect) {
				t.Errorf("expected %v, got %v", test.expect, got.byEntityType())
			}

			after, err := json.Marshal(test.subject.byEntityType())
			if err != nil {
				t.Fatalf("no error expected capturing the subject, got: %v", err)
			}
			if string(after) != string(snapshot) {
				t.Errorf("the subject's own metadata was modified: %s became %s", snapshot, after)
			}
		})
	}
}

func TestApplySuperiorMetadata_NilSubject(t *testing.T) {
	if got := ApplySuperiorMetadata(nil, &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"x@example.com"}}}); got != nil {
		t.Errorf("a subject with no metadata stays without metadata, got %v", got.byEntityType())
	}
}

func TestSupersetOfMerge_ReturnsAnOperatorForEveryValidInput(t *testing.T) {
	tests := []struct {
		name     string
		operand  []any
		incoming any
		expect   []any
	}{
		{
			name:     "two requirements combine into their union",
			operand:  []any{"a"},
			incoming: []any{"b"},
			expect:   []any{"b", "a"},
		},
		{
			name:     "a value both levels require is kept once",
			operand:  []any{"a", "b"},
			incoming: []any{"b", "c"},
			expect:   []any{"b", "c", "a"},
		},
		{
			name:     "two empty requirements stay empty",
			operand:  []any{},
			incoming: []any{},
			expect:   []any{},
		},
		{
			name:     "an empty incoming requirement keeps the current one",
			operand:  []any{"a"},
			incoming: []any{},
			expect:   []any{"a"},
		},
		{
			name:     "no incoming requirement keeps the current one",
			operand:  []any{"a"},
			incoming: nil,
			expect:   []any{"a"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewSupersetOf(test.operand)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}

			merged, err := operator.Merge(test.incoming)
			if err != nil {
				t.Fatalf("no error expected merging, got: %v", err)
			}
			got, ok := merged.OperatorValue().([]any)
			if !ok {
				t.Fatalf("expected an array operand, got %T", merged.OperatorValue())
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("expected %v, got %v", test.expect, got)
			}
		})
	}
}

func TestAddMerge_ProducesTheDeduplicatedUnion(t *testing.T) {
	operator, err := NewAdd([]any{"a", "b"})
	if err != nil {
		t.Fatalf("no error expected building the operator, got: %v", err)
	}

	merged, err := operator.Merge([]any{"b", "c"})
	if err != nil {
		t.Fatalf("no error expected merging, got: %v", err)
	}
	got, ok := merged.OperatorValue().([]any)
	if !ok {
		t.Fatalf("expected an array operand, got %T", merged.OperatorValue())
	}
	if !reflect.DeepEqual(got, []any{"b", "c", "a"}) {
		t.Errorf("expected the deduplicated union, got %v", got)
	}
}

type looseBuiltIn struct {
	identifier string
}

func (l looseBuiltIn) Identifier() string                                    { return l.identifier }
func (l looseBuiltIn) VerifyMetadata(map[string]any) error                   { return nil }
func (l looseBuiltIn) VerifyMetadataPolicy(map[string]PolicyOperators) error { return nil }
func (l looseBuiltIn) VerifyResolvedMetadata(map[string]any) error           { return nil }

func TestVerifyResolved_ARegistrationCannotLoosenABuiltIn(t *testing.T) {
	tests := []struct {
		name     string
		metadata *Metadata
	}{
		{
			name: "openid_relying_party without its required parameter",
			metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
				"client_name": "Leaf RP",
			}},
		},
		{
			name: "openid_provider without its required parameters",
			metadata: &Metadata{OpenIDConnectOpenIDProviderMetadata: &OpenIDConnectOpenIDProviderMetadata{
				"issuer": "https://op.example.com",
			}},
		},
		{
			name: "oauth_authorization_server without its required parameter",
			metadata: &Metadata{OAuthAuthorizationServerMetadata: &OAuthAuthorizationServerMetadata{
				"issuer": "https://as.example.com",
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for entityType := range test.metadata.byEntityType() {
				if err := test.metadata.VerifyResolved(EntityTypeRegistry{entityType: looseBuiltIn{identifier: entityType}}); err == nil {
					t.Errorf("a registration under %s loosened the built-in resolved check", entityType)
				}
			}
		})
	}
}

func TestVerifyResolved_ARegistrationCanTightenABuiltIn(t *testing.T) {
	metadata := &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{
		"redirect_uris": []any{"https://rp.example.com/cb"},
	}}

	if err := metadata.VerifyResolved(nil); err != nil {
		t.Fatalf("the built-in check is satisfied, got: %v", err)
	}

	stricter := EntityTypeRegistry{"openid_relying_party": strictRP{}}
	if err := metadata.VerifyResolved(stricter); err == nil {
		t.Error("a registration must still be able to add its own resolved requirement")
	}
}

type strictRP struct{}

func (strictRP) Identifier() string                                    { return "openid_relying_party" }
func (strictRP) VerifyMetadata(map[string]any) error                   { return nil }
func (strictRP) VerifyMetadataPolicy(map[string]PolicyOperators) error { return nil }
func (strictRP) VerifyResolvedMetadata(metadata map[string]any) error {
	return VerifyRequiredClaims(metadata, "client_name")
}

func TestOpenIDRelyingPartyMetadata_KeyParameterPairIsJudgedAtBothPoints(t *testing.T) {
	both := OpenIDRelyingPartyMetadata{
		"redirect_uris": []any{"https://rp.example.com/cb"},
		"jwks":          map[string]any{"keys": []any{}},
		"jwks_uri":      "https://rp.example.com/jwks",
	}

	if err := both.VerifyMetadata(); err == nil {
		t.Error("expected a statement carrying both key parameters to be refused")
	}
	if err := both.VerifyResolvedMetadata(); err == nil {
		t.Error("expected resolved metadata carrying both key parameters to be refused")
	}
}

func subordinateWith(policy *MetadataPolicy) EntityStatement {
	return EntityStatement{
		Iss:            "https://ta.example.com",
		Sub:            "https://leaf.example.com",
		MetadataPolicy: policy,
	}
}

func TestOperandSlice_RefusesAValueThatIsNotASlice(t *testing.T) {
	tests := map[string]any{
		"a string":        "abc",
		"a number":        float64(1),
		"an object":       map[string]any{"a": "b"},
		"a boolean":       true,
		"no value at all": nil,
	}

	for name, operand := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := NewAdd(operand); err == nil {
				t.Errorf("expected 'add' to refuse a non-slice operand, got %+v", got)
			}
			if got, err := NewSupersetOf(operand); err == nil {
				t.Errorf("expected 'superset_of' to refuse a non-slice operand, got %+v", got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_MergesEveryLevelOfALongChain(t *testing.T) {
	const (
		leaf   = EntityIdentifier("https://leaf.example.com")
		lower  = EntityIdentifier("https://lower.example.com")
		upper  = EntityIdentifier("https://upper.example.com")
		anchor = EntityIdentifier("https://ta.example.com")
	)

	chain := []EntityStatement{
		{Iss: leaf, Sub: leaf},
		{Iss: lower, Sub: leaf, MetadataPolicy: chainPolicy(t, `{"federation_entity":{"contacts":{"add":["lower@example.com"]}}}`)},
		{Iss: upper, Sub: lower, MetadataPolicy: chainPolicy(t, `{"federation_entity":{"contacts":{"add":["upper@example.com"]}}}`)},
		{Iss: anchor, Sub: upper, MetadataPolicy: chainPolicy(t, `{"federation_entity":{"contacts":{"add":["anchor@example.com"]}}}`)},
		{Iss: anchor, Sub: anchor},
	}

	policy, err := ProcessAndExtractPolicy(chain)
	if err != nil {
		t.Fatalf("no error expected extracting the policy, got: %v", err)
	}
	if policy == nil {
		t.Fatal("expected a policy, got none")
	}

	operators, found := policy.FederationMetadata["contacts"]
	if !found {
		t.Fatalf("expected a contacts policy, got %+v", policy.FederationMetadata)
	}
	operands, ok := operators.Metadata[0].OperatorValue().([]any)
	if !ok {
		t.Fatalf("expected an array operand, got %T", operators.Metadata[0].OperatorValue())
	}
	for _, want := range []any{"lower@example.com", "upper@example.com", "anchor@example.com"} {
		if !slices.Contains(operands, want) {
			t.Errorf("expected every level to contribute, %v missing from %v", want, operands)
		}
	}
}

func TestMetadata_SetEntityType_RoutesEveryBuiltInToItsOwnField(t *testing.T) {
	for _, entityType := range builtInEntityTypes {
		t.Run(entityType, func(t *testing.T) {
			var metadata Metadata
			parameters := map[string]any{entityType + "_marker": "set"}
			metadata.setEntityType(entityType, parameters)

			if _, routedToExtensions := metadata.Extensions[entityType]; routedToExtensions {
				t.Fatalf("%s is a built-in type and must not be routed into Extensions", entityType)
			}

			found, present := metadata.byEntityType()[entityType]
			if !present {
				t.Fatalf("%s was not stored anywhere", entityType)
			}
			if !reflect.DeepEqual(found, parameters) {
				t.Errorf("expected %v, got %v", parameters, found)
			}
		})
	}
}

func TestBuiltInEntityTypes_ResolvedChecksAreWiredDeliberately(t *testing.T) {
	withRequiredParameters := map[string]bool{
		"federation_entity":          false,
		"oauth_client":               false,
		"oauth_resource":             false,
		"openid_relying_party":       true,
		"openid_provider":            true,
		"oauth_authorization_server": true,
		"openid_wallet_provider":     true,
		"openid_credential_issuer":   true,
		"openid_credential_verifier": true,
	}

	if len(withRequiredParameters) != len(builtInEntityTypes) {
		t.Fatalf("expected a case for every built-in type, got %d for %d", len(withRequiredParameters), len(builtInEntityTypes))
	}

	for entityType, expected := range withRequiredParameters {
		t.Run(entityType, func(t *testing.T) {
			definition, registered := builtInEntityTypeDefinitions[entityType]
			if !registered {
				t.Fatalf("%s is not registered", entityType)
			}
			builtIn, ok := definition.(builtInEntityType)
			if !ok {
				t.Fatalf("expected a built-in definition, got %T", definition)
			}
			if (builtIn.verifyResolved != nil) != expected {
				t.Errorf("expected a resolved check present=%v for %s, got %v", expected, entityType, builtIn.verifyResolved != nil)
			}
		})
	}
}

func TestOpenIDRelyingPartyMetadata_SignedJwksUriIsNotExclusive(t *testing.T) {
	metadata := OpenIDRelyingPartyMetadata{
		"redirect_uris":   []any{"https://rp.example.com/cb"},
		"jwks":            map[string]any{"keys": []any{}},
		"signed_jwks_uri": "https://rp.example.com/jwks.jose",
	}

	if err := metadata.VerifyMetadata(); err != nil {
		t.Errorf("section 5.2.1.1 recommends one key representation rather than requiring it, got: %v", err)
	}
	if err := metadata.VerifyResolvedMetadata(); err != nil {
		t.Errorf("section 5.2.1.1 recommends one key representation rather than requiring it, got: %v", err)
	}
}
