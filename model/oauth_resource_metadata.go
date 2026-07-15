package model

var (
	_ EntityTypeIdentifier = OAuthResourceMetadata{}
)

type OAuthResourceMetadata map[string]any

func (m OAuthResourceMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := verifyRequiredClaims(m, "resource"); err != nil {
		return err
	}
	if err := verifyHTTPSURLValue("resource", m["resource"], true); err != nil {
		return err
	}
	if err := verifyHTTPSURLClaim(m, "jwks_uri", true); err != nil {
		return err
	}
	if err := verifyAlgValuesClaim(m, "resource_signing_alg_values_supported", false); err != nil {
		return err
	}
	for _, key := range []string{
		"authorization_servers",
		"scopes_supported",
		"bearer_methods_supported",
	} {
		if err := verifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	return nil
}
