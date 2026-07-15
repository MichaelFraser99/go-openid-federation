package model

var (
	_ EntityTypeIdentifier = OAuthAuthorizationServerMetadata{}
)

type OAuthAuthorizationServerMetadata map[string]any

func (m OAuthAuthorizationServerMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := verifyRequiredClaims(m, "issuer", "response_types_supported"); err != nil {
		return err
	}
	if err := verifyHTTPSURLValue("issuer", m["issuer"], false); err != nil {
		return err
	}
	if err := verifyStringArrayClaim(m, "response_types_supported"); err != nil {
		return err
	}
	if err := verifyHTTPSURLClaim(m, "jwks_uri", true); err != nil {
		return err
	}
	for _, key := range []string{
		"scopes_supported",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
		"response_modes_supported",
		"code_challenge_methods_supported",
	} {
		if err := verifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	return nil
}
