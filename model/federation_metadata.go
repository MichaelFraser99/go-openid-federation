package model

import (
	"fmt"
)

var (
	_ EntityTypeIdentifier = FederationMetadata{}
)

type FederationMetadata map[string]any

func (m FederationMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	for _, k := range []string{
		"federation_fetch_endpoint",
		"federation_list_endpoint",
		"federation_resolve_endpoint",
		"federation_trust_mark_status_endpoint",
		"federation_trust_mark_list_endpoint",
		"federation_trust_mark_endpoint",
		"federation_historical_keys_endpoint",
	} {
		if err := VerifyFederationEndpoint(m[k]); err != nil {
			return fmt.Errorf("invalid %s endpoint: %s", k, err.Error())
		}
	}

	if v, ok := m["endpoint_auth_signing_alg_values_supported"]; ok {
		if _, ok := v.([]string); !ok {
			return fmt.Errorf("invalid endpoint_auth_signing_alg_values_supported metadata value")
		}
	}
	return nil
}
