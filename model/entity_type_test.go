package model

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testEntityType struct {
	identifier  string
	metadataErr error
	policyErr   error
	resolvedErr error
}

func (t testEntityType) Identifier() string { return t.identifier }

func (t testEntityType) VerifyMetadata(map[string]any) error { return t.metadataErr }

func (t testEntityType) VerifyMetadataPolicy(map[string]PolicyOperators) error { return t.policyErr }

func (t testEntityType) VerifyResolvedMetadata(map[string]any) error { return t.resolvedErr }

func TestMetadata_UnmarshalJSON_PreservesUnrecognisedEntityTypes(t *testing.T) {
	input := `{
		"federation_entity": {"organization_name": "Example"},
		"openid_verifier_provider": {"vp_formats_supported": {"dc+sd-jwt": {}}}
	}`

	var metadata Metadata
	if err := json.Unmarshal([]byte(input), &metadata); err != nil {
		t.Fatalf("expected no error unmarshalling metadata, got %q", err.Error())
	}

	if metadata.FederationMetadata == nil {
		t.Fatal("expected federation_entity metadata to be parsed")
	}

	extension, ok := metadata.Extensions["openid_verifier_provider"]
	if !ok {
		t.Fatalf("expected openid_verifier_provider to be preserved, got extensions %v", metadata.Extensions)
	}

	expected := map[string]any{"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}}}
	if diff := cmp.Diff(expected, extension); diff != "" {
		t.Errorf("unexpected extension metadata (-want +got):\n%s", diff)
	}
}

func TestMetadata_MarshalJSON_EmitsExtensionsAlongsideBuiltIns(t *testing.T) {
	metadata := Metadata{
		FederationMetadata: &FederationMetadata{"organization_name": "Example"},
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}}},
		},
	}

	marshalled, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("expected no error marshalling metadata, got %q", err.Error())
	}

	var result map[string]any
	if err = json.Unmarshal(marshalled, &result); err != nil {
		t.Fatalf("expected no error unmarshalling result, got %q", err.Error())
	}

	if _, ok := result["federation_entity"]; !ok {
		t.Error("expected federation_entity to be emitted")
	}
	if _, ok := result["openid_verifier_provider"]; !ok {
		t.Errorf("expected openid_verifier_provider to be emitted at the top level, got %s", string(marshalled))
	}
}

func TestMetadataPolicy_RoundTripsUnrecognisedEntityTypes(t *testing.T) {
	input := `{"openid_verifier_provider":{"vp_formats_supported":{"essential":true}}}`

	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(input), &policy); err != nil {
		t.Fatalf("expected no error unmarshalling metadata policy, got %q", err.Error())
	}

	operators, ok := policy.Extensions["openid_verifier_provider"]
	if !ok {
		t.Fatalf("expected openid_verifier_provider policy to be preserved, got extensions %v", policy.Extensions)
	}
	if len(operators["vp_formats_supported"].Metadata) != 1 {
		t.Fatalf("expected one operator for vp_formats_supported, got %d", len(operators["vp_formats_supported"].Metadata))
	}

	marshalled, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("expected no error marshalling metadata policy, got %q", err.Error())
	}
	if string(marshalled) != input {
		t.Errorf("expected round trip to produce %s, got %s", input, string(marshalled))
	}
}

func TestDefaultEntityTypeRegistry_CoversEveryBuiltInType(t *testing.T) {
	registry := DefaultEntityTypeRegistry()

	for _, entityType := range builtInEntityTypes {
		definition, ok := registry[entityType]
		if !ok {
			t.Errorf("expected %s to be present in the default registry", entityType)
			continue
		}
		if definition.Identifier() != entityType {
			t.Errorf("expected %s definition to identify as %s, got %s", entityType, entityType, definition.Identifier())
		}
	}
}

func TestMetadata_Verify_RunsRegisteredExtensionValidation(t *testing.T) {
	validationErr := errors.New("vp_formats_supported is required")
	metadata := Metadata{
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {},
		},
	}

	registry := EntityTypeRegistry{
		"openid_verifier_provider": testEntityType{identifier: "openid_verifier_provider", metadataErr: validationErr},
	}

	err := metadata.Verify(registry, false)
	if err == nil {
		t.Fatal("expected verification to fail for an invalid extension entity type")
	}
	if !errors.Is(err, validationErr) {
		t.Errorf("expected the extension's own error to be wrapped, got %q", err.Error())
	}
}

func TestMetadata_Verify_PreservesUnrecognisedTypesByDefault(t *testing.T) {
	metadata := Metadata{
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {"vp_formats_supported": map[string]any{}},
		},
	}

	if err := metadata.Verify(nil, false); err != nil {
		t.Fatalf("expected no error verifying unrecognised metadata, got %q", err.Error())
	}

	if _, ok := metadata.Extensions["openid_verifier_provider"]; !ok {
		t.Error("expected unrecognised entity type to be preserved")
	}
}

func TestMetadata_Verify_DiscardsUnrecognisedTypesWhenConfigured(t *testing.T) {
	metadata := Metadata{
		FederationMetadata: &FederationMetadata{"organization_name": "Example"},
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {"vp_formats_supported": map[string]any{}},
		},
	}

	if err := metadata.Verify(nil, true); err != nil {
		t.Fatalf("expected no error verifying metadata, got %q", err.Error())
	}

	if _, ok := metadata.Extensions["openid_verifier_provider"]; ok {
		t.Error("expected unrecognised entity type to be discarded")
	}
	if metadata.FederationMetadata == nil {
		t.Error("expected built-in metadata to survive discarding")
	}
}

func TestEntityTypeRegistry_ConsumerEntryOverridesBuiltIn(t *testing.T) {
	overrideErr := errors.New("override applied")
	metadata := Metadata{
		OpenIDWalletProviderMetadata: &OpenIDWalletProviderMetadata{"vp_formats_supported": map[string]any{}},
	}

	registry := EntityTypeRegistry{
		"openid_wallet_provider": testEntityType{identifier: "openid_wallet_provider", metadataErr: overrideErr},
	}

	err := metadata.Verify(registry, false)
	if !errors.Is(err, overrideErr) {
		t.Errorf("expected the consumer override to replace the built-in definition, got %v", err)
	}
}

func TestMetadataPolicy_Verify_RunsRegisteredExtensionPolicyValidation(t *testing.T) {
	policyErr := errors.New("operator not permitted on this type")
	policy := MetadataPolicy{
		Extensions: map[string]map[string]PolicyOperators{
			"openid_verifier_provider": {},
		},
	}

	registry := EntityTypeRegistry{
		"openid_verifier_provider": testEntityType{identifier: "openid_verifier_provider", policyErr: policyErr},
	}

	if err := policy.Verify(registry, false); !errors.Is(err, policyErr) {
		t.Errorf("expected the extension's policy error to be wrapped, got %v", err)
	}
}

func TestMetadata_VerifyResolved_RunsAfterPolicyApplication(t *testing.T) {
	resolvedErr := errors.New("policy stripped a required claim")
	metadata := Metadata{
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {},
		},
	}

	registry := EntityTypeRegistry{
		"openid_verifier_provider": testEntityType{identifier: "openid_verifier_provider", resolvedErr: resolvedErr},
	}

	if err := metadata.VerifyResolved(registry); !errors.Is(err, resolvedErr) {
		t.Errorf("expected the extension's resolved error to be wrapped, got %v", err)
	}
}

func TestApplyPolicy_DoesNotPanicWhenMetadataTypeHasNoPolicy(t *testing.T) {
	subject := EntityStatement{
		Metadata: &Metadata{
			Extensions: map[string]map[string]any{
				"openid_verifier_provider": {"vp_formats_supported": map[string]any{}},
			},
		},
	}

	policy := MetadataPolicy{
		FederationMetadata: map[string]PolicyOperators{},
	}

	result, err := ApplyPolicy(subject, policy)
	if err != nil {
		t.Fatalf("expected no error applying policy, got %q", err.Error())
	}
	if _, ok := result.Metadata.Extensions["openid_verifier_provider"]; !ok {
		t.Error("expected extension metadata to survive policy application")
	}
}

func TestApplyPolicy_AppliesPolicyToExtensionMetadata(t *testing.T) {
	value, err := NewValue("Example Verifier")
	if err != nil {
		t.Fatalf("expected no error creating value operator, got %q", err.Error())
	}

	subject := EntityStatement{
		Metadata: &Metadata{
			Extensions: map[string]map[string]any{
				"openid_verifier_provider": {"organization_name": "Original"},
			},
		},
	}

	policy := MetadataPolicy{
		Extensions: map[string]map[string]PolicyOperators{
			"openid_verifier_provider": {
				"organization_name": {Metadata: []MetadataPolicyOperator{*value}},
			},
		},
	}

	result, err := ApplyPolicy(subject, policy)
	if err != nil {
		t.Fatalf("expected no error applying policy, got %q", err.Error())
	}

	got := result.Metadata.Extensions["openid_verifier_provider"]["organization_name"]
	if got != "Example Verifier" {
		t.Errorf("expected policy to be applied to extension metadata, got %v", got)
	}
}

func TestMetadata_FilterByEntityTypes_FiltersExtensions(t *testing.T) {
	metadata := Metadata{
		FederationMetadata: &FederationMetadata{"organization_name": "Example"},
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {"vp_formats_supported": map[string]any{}},
			"example_custom_type":      {"foo": "bar"},
		},
	}

	metadata.FilterByEntityTypes([]string{"openid_verifier_provider"})

	if metadata.FederationMetadata != nil {
		t.Error("expected federation_entity to be filtered out")
	}
	if _, ok := metadata.Extensions["openid_verifier_provider"]; !ok {
		t.Error("expected openid_verifier_provider to be retained")
	}
	if _, ok := metadata.Extensions["example_custom_type"]; ok {
		t.Error("expected example_custom_type to be filtered out")
	}
}

func TestDefaultEntityTypeRegistry_DelegatesToTheCorrectValidator(t *testing.T) {
	tests := map[string]struct {
		metadata      map[string]any
		expectedError string
	}{
		"federation_entity": {
			metadata:      map[string]any{"federation_fetch_endpoint": "http://insecure.example.com"},
			expectedError: "invalid federation_fetch_endpoint endpoint",
		},
		"openid_relying_party": {
			metadata:      map[string]any{"client_name": "Example"},
			expectedError: "missing required 'redirect_uris' claim",
		},
		"openid_provider": {
			metadata:      map[string]any{"issuer": "https://example.com"},
			expectedError: "missing required 'authorization_endpoint' claim",
		},
		"oauth_authorization_server": {
			metadata:      map[string]any{"issuer": "https://example.com"},
			expectedError: "missing required 'response_types_supported' claim",
		},
		"oauth_client": {
			metadata:      map[string]any{"jwks_uri": "http://insecure.example.com"},
			expectedError: "'jwks_uri' must use the 'https' scheme",
		},
		"oauth_resource": {
			metadata:      map[string]any{"client_name": "Example"},
			expectedError: "missing required 'resource' claim",
		},
		"openid_wallet_provider": {
			metadata:      map[string]any{"vp_formats_supported": map[string]any{}, "client_id_prefixes_supported": []any{}},
			expectedError: "'client_id_prefixes_supported' must not be empty",
		},
		"openid_credential_issuer": {
			metadata:      map[string]any{"client_name": "Example"},
			expectedError: "missing required 'credential_issuer' claim",
		},
		"openid_credential_verifier": {
			metadata:      map[string]any{"vp_formats_supported": map[string]any{}, "request_uris": "not-an-array"},
			expectedError: "'request_uris' must be an array of strings",
		},
	}

	registry := DefaultEntityTypeRegistry()

	for entityType, tt := range tests {
		t.Run(entityType, func(t *testing.T) {
			definition, ok := registry[entityType]
			if !ok {
				t.Fatalf("expected %s to be registered", entityType)
			}

			err := definition.VerifyMetadata(tt.metadata)
			if err == nil {
				t.Fatalf("expected %s validation to reject the metadata, got nil", entityType)
			}
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("expected %s to be validated by its own rules producing %q, got %q", entityType, tt.expectedError, err.Error())
			}
		})
	}

	for entityType := range tests {
		if len(builtInEntityTypes) != len(tests) {
			t.Fatalf("expected a delegation case for every built-in entity type, got %d cases for %d types", len(tests), len(builtInEntityTypes))
		}
		if !slices.Contains(builtInEntityTypes, entityType) {
			t.Errorf("test case %s is not a built-in entity type", entityType)
		}
	}
}

func TestDefaultEntityTypeRegistry_BuiltInPolicyAndResolvedHooksAcceptAnything(t *testing.T) {
	registry := DefaultEntityTypeRegistry()

	for _, entityType := range builtInEntityTypes {
		definition := registry[entityType]
		if err := definition.VerifyMetadataPolicy(map[string]PolicyOperators{"anything": {}}); err != nil {
			t.Errorf("expected %s policy validation to accept anything, got %q", entityType, err.Error())
		}
		if err := definition.VerifyResolvedMetadata(map[string]any{"anything": "goes"}); err != nil {
			t.Errorf("expected %s resolved validation to accept anything, got %q", entityType, err.Error())
		}
	}
}

func TestMetadataPolicy_SetEntityType_RoutesEveryBuiltInToItsOwnField(t *testing.T) {
	for _, entityType := range builtInEntityTypes {
		t.Run(entityType, func(t *testing.T) {
			var policy MetadataPolicy
			operators := map[string]PolicyOperators{entityType + "_marker": {}}

			policy.setEntityType(entityType, operators)

			if len(policy.Extensions) != 0 {
				t.Errorf("expected built-in %s to be routed to its own field, not extensions", entityType)
			}

			stored, ok := policy.byEntityType()[entityType]
			if !ok || stored == nil {
				t.Fatalf("expected %s to be readable back, got %v", entityType, stored)
			}
			if _, ok = stored[entityType+"_marker"]; !ok {
				t.Errorf("expected %s to round trip its own operators, got %v", entityType, stored)
			}
		})
	}
}

func TestMetadataPolicy_SetEntityType_RoutesUnrecognisedTypesToExtensions(t *testing.T) {
	var policy MetadataPolicy
	policy.setEntityType("openid_verifier_provider", map[string]PolicyOperators{"organization_name": {}})

	if _, ok := policy.Extensions["openid_verifier_provider"]; !ok {
		t.Errorf("expected unrecognised entity type to be routed to extensions, got %v", policy.Extensions)
	}
}

func TestMetadataPolicy_Verify_DiscardsUnrecognisedTypesWhenConfigured(t *testing.T) {
	policy := MetadataPolicy{
		FederationMetadata: map[string]PolicyOperators{"organization_name": {}},
		Extensions: map[string]map[string]PolicyOperators{
			"openid_verifier_provider": {"organization_name": {}},
		},
	}

	if err := policy.Verify(nil, true); err != nil {
		t.Fatalf("expected no error verifying metadata policy, got %q", err.Error())
	}

	if _, ok := policy.Extensions["openid_verifier_provider"]; ok {
		t.Error("expected unrecognised entity type policy to be discarded")
	}
	if policy.FederationMetadata == nil {
		t.Error("expected built-in policy to survive discarding")
	}
}

func TestMetadataPolicy_Verify_PreservesUnrecognisedTypesByDefault(t *testing.T) {
	policy := MetadataPolicy{
		Extensions: map[string]map[string]PolicyOperators{
			"openid_verifier_provider": {"organization_name": {}},
		},
	}

	if err := policy.Verify(nil, false); err != nil {
		t.Fatalf("expected no error verifying metadata policy, got %q", err.Error())
	}
	if _, ok := policy.Extensions["openid_verifier_provider"]; !ok {
		t.Error("expected unrecognised entity type policy to be preserved")
	}
}

func TestProcessAndExtractPolicy_MergesExtensionPoliciesDownTheChain(t *testing.T) {
	subsetOf, err := NewSubsetOf([]any{"a", "b", "c"})
	if err != nil {
		t.Fatalf("expected no error creating subset_of operator, got %q", err.Error())
	}
	supersetOf, err := NewSupersetOf([]any{"a"})
	if err != nil {
		t.Fatalf("expected no error creating superset_of operator, got %q", err.Error())
	}

	chain := []EntityStatement{
		{
			MetadataPolicy: &MetadataPolicy{
				Extensions: map[string]map[string]PolicyOperators{
					"openid_verifier_provider": {
						"formats": {Metadata: []MetadataPolicyOperator{*subsetOf}},
					},
				},
			},
		},
		{
			MetadataPolicy: &MetadataPolicy{
				Extensions: map[string]map[string]PolicyOperators{
					"openid_verifier_provider": {
						"formats": {Metadata: []MetadataPolicyOperator{*supersetOf}},
					},
				},
			},
		},
	}

	merged, err := ProcessAndExtractPolicy(chain)
	if err != nil {
		t.Fatalf("expected no error merging policies, got %q", err.Error())
	}

	operators, ok := merged.Extensions["openid_verifier_provider"]
	if !ok {
		t.Fatalf("expected merged extension policy, got %v", merged.Extensions)
	}
	if len(operators["formats"].Metadata) != 2 {
		t.Errorf("expected both operators to survive the merge, got %d", len(operators["formats"].Metadata))
	}
}

func TestProcessAndExtractPolicy_AddsExtensionPolicyAbsentFromTheAccumulator(t *testing.T) {
	value, err := NewValue("Example")
	if err != nil {
		t.Fatalf("expected no error creating value operator, got %q", err.Error())
	}

	chain := []EntityStatement{
		{
			MetadataPolicy: &MetadataPolicy{
				FederationMetadata: map[string]PolicyOperators{"organization_name": {}},
			},
		},
		{
			MetadataPolicy: &MetadataPolicy{
				Extensions: map[string]map[string]PolicyOperators{
					"openid_verifier_provider": {
						"organization_name": {Metadata: []MetadataPolicyOperator{*value}},
					},
				},
			},
		},
	}

	merged, err := ProcessAndExtractPolicy(chain)
	if err != nil {
		t.Fatalf("expected no error merging policies, got %q", err.Error())
	}

	if _, ok := merged.Extensions["openid_verifier_provider"]; !ok {
		t.Errorf("expected the extension policy to be carried into the accumulator, got %v", merged.Extensions)
	}
}

func TestMetadataPolicy_UnmarshalJSON_RejectsMalformedExtension(t *testing.T) {
	var policy MetadataPolicy
	err := json.Unmarshal([]byte(`{"openid_verifier_provider":"not-an-object"}`), &policy)
	if err == nil {
		t.Fatal("expected malformed extension policy to be rejected")
	}
	if !strings.Contains(err.Error(), "openid_verifier_provider") {
		t.Errorf("expected the error to name the offending entity type, got %q", err.Error())
	}
}

func TestBuiltInEntityType_WithoutValidatorAcceptsAnything(t *testing.T) {
	definition := builtInEntityType{identifier: "example_type"}

	if err := definition.VerifyMetadata(map[string]any{"anything": "goes"}); err != nil {
		t.Errorf("expected a definition without a validator to accept anything, got %q", err.Error())
	}
}

func TestMetadata_VerifyResolved_SkipsUnrecognisedTypes(t *testing.T) {
	metadata := Metadata{
		Extensions: map[string]map[string]any{
			"openid_verifier_provider": {},
		},
	}

	if err := metadata.VerifyResolved(nil); err != nil {
		t.Errorf("expected unrecognised entity types to be skipped, got %q", err.Error())
	}
	if _, ok := metadata.Extensions["openid_verifier_provider"]; !ok {
		t.Error("expected resolved verification to leave unrecognised entity types in place")
	}
}
