package model

import (
	"testing"
)

func TestApplyPolicy_CoversNewEntityTypes(t *testing.T) {
	scopeAdd, err := NewAdd([]any{"phone"})
	if err != nil {
		t.Fatalf("failed to construct add operator: %s", err.Error())
	}
	authValue, err := NewValue("private_key_jwt")
	if err != nil {
		t.Fatalf("failed to construct value operator: %s", err.Error())
	}
	walletPrefixes, err := NewValue([]any{"redirect_uri"})
	if err != nil {
		t.Fatalf("failed to construct value operator: %s", err.Error())
	}

	subject := EntityStatement{
		Metadata: &Metadata{
			OAuthClientMetadata: &OAuthClientMetadata{
				"scope": "openid address",
			},
			OpenIDWalletProviderMetadata: &OpenIDWalletProviderMetadata{
				"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
			},
		},
	}

	policy := MetadataPolicy{
		OAuthClientMetadata: map[string]PolicyOperators{
			"scope":                      {Metadata: []MetadataPolicyOperator{*scopeAdd}},
			"token_endpoint_auth_method": {Metadata: []MetadataPolicyOperator{*authValue}},
		},
		OpenIDWalletProviderMetadata: map[string]PolicyOperators{
			"client_id_prefixes_supported": {Metadata: []MetadataPolicyOperator{*walletPrefixes}},
		},
	}

	result, err := ApplyPolicy(subject, policy)
	if err != nil {
		t.Fatalf("expected no error applying policy, got %q", err.Error())
	}

	client := *result.Metadata.OAuthClientMetadata
	if client["scope"] != "openid address phone" {
		t.Errorf("expected oauth_client scope %q, got %v", "openid address phone", client["scope"])
	}
	if client["token_endpoint_auth_method"] != "private_key_jwt" {
		t.Errorf("expected oauth_client token_endpoint_auth_method %q, got %v", "private_key_jwt", client["token_endpoint_auth_method"])
	}

	wallet := *result.Metadata.OpenIDWalletProviderMetadata
	prefixes, ok := wallet["client_id_prefixes_supported"].([]any)
	if !ok || len(prefixes) != 1 || prefixes[0] != "redirect_uri" {
		t.Errorf("expected wallet client_id_prefixes_supported [redirect_uri], got %v", wallet["client_id_prefixes_supported"])
	}
}

func TestProcessAndExtractPolicy_CoversNewEntityTypes(t *testing.T) {
	addA, err := NewAdd([]any{"ops-a@example.com"})
	if err != nil {
		t.Fatalf("failed to construct add operator: %s", err.Error())
	}
	addB, err := NewAdd([]any{"ops-b@example.com"})
	if err != nil {
		t.Fatalf("failed to construct add operator: %s", err.Error())
	}

	chain := []EntityStatement{
		{
			MetadataPolicy: &MetadataPolicy{
				OAuthResourceMetadata: map[string]PolicyOperators{
					"contacts": {Metadata: []MetadataPolicyOperator{*addA}},
				},
			},
		},
		{
			MetadataPolicy: &MetadataPolicy{
				OAuthResourceMetadata: map[string]PolicyOperators{
					"contacts": {Metadata: []MetadataPolicyOperator{*addB}},
				},
			},
		},
	}

	merged, err := ProcessAndExtractPolicy(chain)
	if err != nil {
		t.Fatalf("expected no error merging policy, got %q", err.Error())
	}
	if merged.OAuthResourceMetadata == nil {
		t.Fatal("expected merged oauth_resource policy to be present")
	}
	if _, ok := merged.OAuthResourceMetadata["contacts"]; !ok {
		t.Errorf("expected merged oauth_resource policy to contain 'contacts', got %v", merged.OAuthResourceMetadata)
	}
}

func TestMetadata_FilterByEntityTypes(t *testing.T) {
	newMetadata := func() *Metadata {
		return &Metadata{
			FederationMetadata:           &FederationMetadata{"organization_name": "Example"},
			OAuthClientMetadata:          &OAuthClientMetadata{"client_name": "Example"},
			OpenIDWalletProviderMetadata: &OpenIDWalletProviderMetadata{"vp_formats_supported": map[string]any{}},
		}
	}

	t.Run("empty entity types leaves metadata untouched", func(t *testing.T) {
		m := newMetadata()
		m.FilterByEntityTypes(nil)
		if m.FederationMetadata == nil || m.OAuthClientMetadata == nil || m.OpenIDWalletProviderMetadata == nil {
			t.Error("expected all metadata to be retained when no entity types are requested")
		}
	})

	t.Run("retains only requested types", func(t *testing.T) {
		m := newMetadata()
		m.FilterByEntityTypes([]string{"oauth_client"})
		if m.OAuthClientMetadata == nil {
			t.Error("expected oauth_client metadata to be retained")
		}
		if m.FederationMetadata != nil {
			t.Error("expected federation_entity metadata to be filtered out")
		}
		if m.OpenIDWalletProviderMetadata != nil {
			t.Error("expected openid_wallet_provider metadata to be filtered out")
		}
	})

	t.Run("retains multiple requested types", func(t *testing.T) {
		m := newMetadata()
		m.FilterByEntityTypes([]string{"oauth_client", "openid_wallet_provider"})
		if m.OAuthClientMetadata == nil || m.OpenIDWalletProviderMetadata == nil {
			t.Error("expected both requested types to be retained")
		}
		if m.FederationMetadata != nil {
			t.Error("expected federation_entity metadata to be filtered out")
		}
	})
}
