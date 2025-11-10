package model

import (
	"testing"
)

func TestFederationMetadata_VerifyMetadata(t *testing.T) {
	tests := map[string]struct {
		metadata FederationMetadata
		validate func(t *testing.T, err error)
	}{
		"empty metadata is valid": {
			metadata: FederationMetadata{},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for empty metadata, got %q", err.Error())
				}
			},
		},
		"valid federation_fetch_endpoint": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": "https://example.com/fetch",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_fetch_endpoint, got %q", err.Error())
				}
			},
		},
		"valid federation_list_endpoint": {
			metadata: FederationMetadata{
				"federation_list_endpoint": "https://example.com/list",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_list_endpoint, got %q", err.Error())
				}
			},
		},
		"valid federation_resolve_endpoint": {
			metadata: FederationMetadata{
				"federation_resolve_endpoint": "https://example.com/resolve",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_resolve_endpoint, got %q", err.Error())
				}
			},
		},
		"valid federation_trust_mark_status_endpoint": {
			metadata: FederationMetadata{
				"federation_trust_mark_status_endpoint": "https://example.com/trust-mark-status",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_trust_mark_status_endpoint, got %q", err.Error())
				}
			},
		},
		"valid federation_trust_mark_list_endpoint": {
			metadata: FederationMetadata{
				"federation_trust_mark_list_endpoint": "https://example.com/trust-mark-list",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_trust_mark_list_endpoint, got %q", err.Error())
				}
			},
		},
		"valid federation_trust_mark_endpoint": {
			metadata: FederationMetadata{
				"federation_trust_mark_endpoint": "https://example.com/trust-mark",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_trust_mark_endpoint, got %q", err.Error())
				}
			},
		},
		"valid federation_historical_keys_endpoint": {
			metadata: FederationMetadata{
				"federation_historical_keys_endpoint": "https://example.com/historical-keys",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid federation_historical_keys_endpoint, got %q", err.Error())
				}
			},
		},
		"all valid endpoints together": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint":             "https://example.com/fetch",
				"federation_list_endpoint":              "https://example.com/list",
				"federation_resolve_endpoint":           "https://example.com/resolve",
				"federation_trust_mark_status_endpoint": "https://example.com/trust-mark-status",
				"federation_trust_mark_list_endpoint":   "https://example.com/trust-mark-list",
				"federation_trust_mark_endpoint":        "https://example.com/trust-mark",
				"federation_historical_keys_endpoint":   "https://example.com/historical-keys",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for all valid endpoints, got %q", err.Error())
				}
			},
		},
		"invalid federation_fetch_endpoint - not a string": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": 123,
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for non-string endpoint, got nil")
				}
			},
		},
		"invalid federation_fetch_endpoint - not https": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": "http://example.com/fetch",
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for non-https endpoint, got nil")
				}
			},
		},
		"invalid federation_fetch_endpoint - contains fragment": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": "https://example.com/fetch#fragment",
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for endpoint with fragment, got nil")
				}
			},
		},
		"invalid federation_list_endpoint - malformed URL": {
			metadata: FederationMetadata{
				"federation_list_endpoint": "not a valid url",
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for malformed URL, got nil")
				}
			},
		},
		"valid endpoint_auth_signing_alg_values_supported - string array": {
			metadata: FederationMetadata{
				"endpoint_auth_signing_alg_values_supported": []string{"RS256", "ES256"},
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for valid endpoint_auth_signing_alg_values_supported, got %q", err.Error())
				}
			},
		},
		"invalid endpoint_auth_signing_alg_values_supported - not a string array": {
			metadata: FederationMetadata{
				"endpoint_auth_signing_alg_values_supported": "RS256",
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for invalid endpoint_auth_signing_alg_values_supported type, got nil")
				}
			},
		},
		"invalid endpoint_auth_signing_alg_values_supported - array of non-strings": {
			metadata: FederationMetadata{
				"endpoint_auth_signing_alg_values_supported": []int{1, 2, 3},
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error for endpoint_auth_signing_alg_values_supported with non-string elements, got nil")
				}
			},
		},
		"nil endpoint is valid": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": nil,
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for nil endpoint, got %q", err.Error())
				}
			},
		},
		"multiple endpoints with one invalid": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint":   "https://example.com/fetch",
				"federation_list_endpoint":    "http://example.com/list",
				"federation_resolve_endpoint": "https://example.com/resolve",
			},
			validate: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error when one endpoint is invalid, got nil")
				}
			},
		},
		"other metadata fields are allowed": {
			metadata: FederationMetadata{
				"organization_name": "Example Organization",
				"contacts":          []string{"admin@example.com"},
				"custom_field":      "custom_value",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for metadata with other fields, got %q", err.Error())
				}
			},
		},
		"federation_fetch_endpoint with query parameters": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": "https://example.com/fetch?param=value",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for endpoint with query parameters, got %q", err.Error())
				}
			},
		},
		"federation_fetch_endpoint with port": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": "https://example.com:8443/fetch",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for endpoint with port, got %q", err.Error())
				}
			},
		},
		"federation_fetch_endpoint with path": {
			metadata: FederationMetadata{
				"federation_fetch_endpoint": "https://example.com/path/to/fetch",
			},
			validate: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error for endpoint with path, got %q", err.Error())
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.metadata.VerifyMetadata()
			tt.validate(t, err)
		})
	}
}
