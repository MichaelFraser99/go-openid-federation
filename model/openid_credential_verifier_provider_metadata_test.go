package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenIDCredentialVerifierProviderMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDCredentialVerifierProviderMetadata
		says     string
	}{
		"empty metadata is valid": {
			metadata: OpenIDCredentialVerifierProviderMetadata{},
		},
		"a jwks holding the attestation signing key": {
			metadata: OpenIDCredentialVerifierProviderMetadata{"jwks": map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"}}}},
		},
		"a jwks that is not a JWK Set": {
			metadata: OpenIDCredentialVerifierProviderMetadata{"jwks": []any{}},
			says:     "'jwks' must be a JSON object",
		},
		"a jwks_uri over plain http": {
			metadata: OpenIDCredentialVerifierProviderMetadata{"jwks_uri": "http://provider.example.com/jwks"},
			says:     "'jwks_uri' must use the 'https' scheme",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyMetadata()
			if tt.says == "" {
				if err != nil {
					t.Errorf("expected the metadata to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.says) {
				t.Errorf("expected a refusal containing %q, got %v", tt.says, err)
			}
		})
	}
}

func TestOpenIDCredentialVerifierProviderMetadata_VerifyResolvedMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata OpenIDCredentialVerifierProviderMetadata
		says     string
	}{
		"an empty object does not publish the attestation signing keys": {
			metadata: OpenIDCredentialVerifierProviderMetadata{},
			says:     "missing required 'jwks' claim",
		},
		"keys published only by jwks_uri": {
			metadata: OpenIDCredentialVerifierProviderMetadata{"jwks_uri": "https://provider.example.com/jwks"},
			says:     "missing required 'jwks' claim",
		},
		"keys published only by signed_jwks_uri": {
			metadata: OpenIDCredentialVerifierProviderMetadata{"signed_jwks_uri": "https://provider.example.com/jwks.jose"},
			says:     "missing required 'jwks' claim",
		},
		"keys published in jwks": {
			metadata: OpenIDCredentialVerifierProviderMetadata{"jwks": map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"}}}},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyResolvedMetadata()
			if tt.says == "" {
				if err != nil {
					t.Errorf("[Wallet draft 06 6.2] expected the metadata to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.says) {
				t.Errorf("[Wallet draft 06 6.2] expected a refusal containing %q, got %v", tt.says, err)
			}
		})
	}
}

func TestOpenIDCredentialVerifierProvider_IsABuiltInTypeThroughEveryCodec(t *testing.T) {
	const metadataJSON = `{"federation_entity":{"organization_name":"Provider"},"openid_credential_verifier_provider":{"jwks":{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"att"}]}}}`

	var metadata Metadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("expected the metadata to parse, got %v", err)
	}
	if metadata.OpenIDCredentialVerifierProviderMetadata == nil {
		t.Fatalf("expected the typed field to be set, got extensions %v", metadata.Extensions)
	}
	if _, inExtensions := metadata.Extensions["openid_credential_verifier_provider"]; inExtensions {
		t.Errorf("expected the type not to be held in Extensions")
	}
	if _, listed := metadata.byEntityType()["openid_credential_verifier_provider"]; !listed {
		t.Errorf("expected byEntityType to list the type")
	}
	written, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("expected the metadata to marshal, got %v", err)
	}
	if !strings.Contains(string(written), `"openid_credential_verifier_provider":{"jwks"`) {
		t.Errorf("expected the type to be written, got %s", written)
	}

	if err := json.Unmarshal([]byte(`{"openid_credential_verifier_provider":{"jwks":"not-a-key-set"}}`), &Metadata{}); err == nil || !strings.Contains(err.Error(), "invalid openid credential verifier provider metadata") {
		t.Errorf("expected parsing to apply the type's own rules, got %v", err)
	}

	kept := metadata
	kept.filterByEntityTypes([]string{"openid_credential_verifier_provider"})
	if kept.OpenIDCredentialVerifierProviderMetadata == nil || kept.FederationMetadata != nil {
		t.Errorf("expected the filter to keep only the named type")
	}
	dropped := metadata
	dropped.filterByEntityTypes([]string{"federation_entity"})
	if dropped.OpenIDCredentialVerifierProviderMetadata != nil {
		t.Errorf("expected the filter to drop the type when it is not named")
	}

	const policyJSON = `{"openid_credential_verifier_provider":{"jwks":{"essential":true}}}`
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		t.Fatalf("expected the policy to parse, got %v", err)
	}
	if policy.OpenIDCredentialVerifierProviderMetadata == nil {
		t.Fatalf("expected the typed policy field to be set, got extensions %v", policy.Extensions)
	}
	if _, listed := policy.byEntityType()["openid_credential_verifier_provider"]; !listed {
		t.Errorf("expected the policy's byEntityType to list the type")
	}
	writtenPolicy, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("expected the policy to marshal, got %v", err)
	}
	if string(writtenPolicy) != policyJSON {
		t.Errorf("expected %s, got %s", policyJSON, writtenPolicy)
	}
	if err := json.Unmarshal([]byte(`{"openid_credential_verifier_provider":"not-an-object"}`), &MetadataPolicy{}); err == nil || !strings.Contains(err.Error(), "malformed openid credential verifier provider metadata policy") {
		t.Errorf("expected a non-object policy to be refused as malformed, got %v", err)
	}
}
