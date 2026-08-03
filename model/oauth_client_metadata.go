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
		if err := VerifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	if err := VerifyObjectClaim(m, "jwks"); err != nil {
		return err
	}
	if err := VerifyHTTPSURLClaim(m, "jwks_uri", true); err != nil {
		return err
	}
	return nil
}
