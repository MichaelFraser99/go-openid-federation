package model

import (
	"fmt"
)

var (
	_ EntityTypeIdentifier = OpenIDRelyingPartyMetadata{}
)

type OpenIDRelyingPartyMetadata map[string]any

func (m OpenIDRelyingPartyMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyRequiredClaims(m, "redirect_uris"); err != nil {
		return err
	}
	for _, key := range []string{
		"redirect_uris",
		"client_registration_types",
		"grant_types",
		"response_types",
		"contacts",
	} {
		if err := VerifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	_, hasJWKs := m["jwks"]
	_, hasJWKsURI := m["jwks_uri"]
	if hasJWKs && hasJWKsURI {
		return fmt.Errorf("'jwks' and 'jwks_uri' must not be used together")
	}
	if err := VerifyObjectClaim(m, "jwks"); err != nil {
		return err
	}
	if err := VerifyHTTPSURLClaim(m, "jwks_uri", true); err != nil {
		return err
	}
	if err := VerifyHTTPSURLClaim(m, "signed_jwks_uri", true); err != nil {
		return err
	}
	return nil
}
