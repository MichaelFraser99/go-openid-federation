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
	if err := VerifyHTTPSURLClaim(m, "issuer", false); err != nil {
		return err
	}
	for _, key := range []string{
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"signed_jwks_uri",
		"userinfo_endpoint",
		"registration_endpoint",
		"federation_registration_endpoint",
	} {
		if err := VerifyHTTPSURLClaim(m, key, true); err != nil {
			return err
		}
	}
	if err := VerifyObjectClaim(m, "jwks"); err != nil {
		return err
	}
	if err := VerifyAlgValuesClaim(m, "id_token_signing_alg_values_supported", true); err != nil {
		return err
	}
	for _, key := range []string{
		"request_object_signing_alg_values_supported",
		"userinfo_signing_alg_values_supported",
	} {
		if err := VerifyAlgValuesClaim(m, key, true); err != nil {
			return err
		}
	}
	if err := VerifyAlgValuesClaim(m, "token_endpoint_auth_signing_alg_values_supported", false); err != nil {
		return err
	}
	for _, key := range []string{
		"response_types_supported",
		"subject_types_supported",
		"client_registration_types_supported",
		"scopes_supported",
		"claims_supported",
		"grant_types_supported",
		"response_modes_supported",
	} {
		if err := VerifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	return nil
}

func (m OpenIDConnectOpenIDProviderMetadata) VerifyResolvedMetadata() error {
	if len(m) == 0 {
		return nil
	}
	if err := VerifyRequiredClaims(m,
		"issuer",
		"authorization_endpoint",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	); err != nil {
		return err
	}
	if !hasKeyMechanism(m) {
		return fmt.Errorf("one of 'jwks', 'jwks_uri', or 'signed_jwks_uri' is required")
	}
	if responseTypesRequireTokenEndpoint(m) {
		if _, ok := m["token_endpoint"]; !ok {
			return fmt.Errorf("missing required 'token_endpoint' claim")
		}
	}
	return nil
}
