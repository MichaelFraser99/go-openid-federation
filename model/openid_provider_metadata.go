package model

import (
	"fmt"
)

var (
	_ EntityTypeIdentifier = OpenIDConnectOpenIDProviderMetadata{}
)

type OpenIDConnectOpenIDProviderMetadata map[string]any

func (m OpenIDConnectOpenIDProviderMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	for _, k := range []string{
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"client_registration_types_supported",
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
	} {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing required '%s' claim", k)
		}
	}
	return nil
}
