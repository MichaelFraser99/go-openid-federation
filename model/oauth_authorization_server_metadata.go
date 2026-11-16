package model

import (
	"fmt"
	"slices"
)

var (
	_ EntityTypeIdentifier = OAuthAuthorizationServerMetadata{}
)

type OAuthAuthorizationServerMetadata map[string]any

func (m OAuthAuthorizationServerMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyHTTPSURLClaim(m, "issuer", false); err != nil {
		return err
	}
	if err := VerifyStringArrayClaim(m, "response_types_supported"); err != nil {
		return err
	}
	for _, key := range []string{
		"token_endpoint_auth_signing_alg_values_supported",
		"revocation_endpoint_auth_signing_alg_values_supported",
		"introspection_endpoint_auth_signing_alg_values_supported",
	} {
		if err := VerifyAlgValuesClaim(m, key, false); err != nil {
			return err
		}
	}
	if err := VerifyJWKSetClaims(m); err != nil {
		return err
	}
	for _, key := range []string{
		"scopes_supported",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
		"response_modes_supported",
		"code_challenge_methods_supported",
	} {
		if err := VerifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	return nil
}

func (m OAuthAuthorizationServerMetadata) VerifyResolvedMetadata() error {
	if err := VerifyRequiredClaims(m, "issuer", "response_types_supported"); err != nil {
		return err
	}
	grantTypes := supportedGrantTypes(m)
	if slices.Contains(grantTypes, "authorization_code") || slices.Contains(grantTypes, "implicit") {
		if _, ok := m["authorization_endpoint"]; !ok {
			return fmt.Errorf("missing required 'authorization_endpoint' claim, since a supported grant type uses the authorization endpoint")
		}
	}
	onlyImplicit := len(grantTypes) > 0 && !slices.ContainsFunc(grantTypes, func(grantType string) bool { return grantType != "implicit" })
	if !onlyImplicit {
		if _, ok := m["token_endpoint"]; !ok {
			return fmt.Errorf("missing required 'token_endpoint' claim, since implicit is not the only supported grant type")
		}
	}
	for _, endpoint := range []string{"token_endpoint", "revocation_endpoint", "introspection_endpoint"} {
		methods, _ := MetadataStringSlice(m[endpoint+"_auth_methods_supported"])
		if !slices.Contains(methods, "private_key_jwt") && !slices.Contains(methods, "client_secret_jwt") {
			continue
		}
		if _, ok := m[endpoint+"_auth_signing_alg_values_supported"]; !ok {
			return fmt.Errorf("missing required '%s_auth_signing_alg_values_supported' claim, since '%s_auth_methods_supported' names private_key_jwt or client_secret_jwt", endpoint, endpoint)
		}
	}
	return nil
}

func supportedGrantTypes(m map[string]any) []string {
	v, ok := m["grant_types_supported"]
	if !ok || v == nil {
		return []string{"authorization_code", "implicit"}
	}
	grantTypes, _ := MetadataStringSlice(v)
	return grantTypes
}
