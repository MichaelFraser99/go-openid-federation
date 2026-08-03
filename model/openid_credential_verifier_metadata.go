package model

var (
	_ EntityTypeIdentifier = OpenIDCredentialVerifierMetadata{}
)

type OpenIDCredentialVerifierMetadata map[string]any

func (m OpenIDCredentialVerifierMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyRequiredClaims(m, "vp_formats_supported"); err != nil {
		return err
	}
	if err := VerifyObjectClaim(m, "vp_formats_supported"); err != nil {
		return err
	}
	for _, key := range []string{
		"redirect_uris",
		"request_uris",
		"response_uris",
	} {
		if err := VerifyStringArrayClaim(m, key); err != nil {
			return err
		}
	}
	if err := VerifyObjectClaim(m, "jwks"); err != nil {
		return err
	}
	return nil
}
