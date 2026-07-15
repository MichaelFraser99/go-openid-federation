package model

var (
	_ EntityTypeIdentifier = OAuthClientMetadata{}
)

type OAuthClientMetadata map[string]any

func (m OAuthClientMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	for _, key := range []string{
		"redirect_uris",
		"grant_types",
		"response_types",
		"contacts",
	} {
		if err := verifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	if err := verifyObjectClaim(m, "jwks"); err != nil {
		return err
	}
	if err := verifyHTTPSURLClaim(m, "jwks_uri", true); err != nil {
		return err
	}
	return nil
}
