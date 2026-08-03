package model

var (
	_ EntityTypeIdentifier = OAuthAuthorizationServerMetadata{}
)

type OAuthAuthorizationServerMetadata map[string]any

func (m OAuthAuthorizationServerMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyRequiredClaims(m, "issuer", "response_types_supported"); err != nil {
		return err
	}
	if err := verifyHTTPSURLValue("issuer", m["issuer"], false); err != nil {
		return err
	}
	if err := VerifyStringArrayClaim(m, "response_types_supported"); err != nil {
		return err
	}
	if err := VerifyHTTPSURLClaim(m, "jwks_uri", true); err != nil {
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
