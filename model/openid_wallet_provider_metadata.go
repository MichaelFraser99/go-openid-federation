package model

var (
	_ EntityTypeIdentifier = OpenIDWalletProviderMetadata{}
)

type OpenIDWalletProviderMetadata map[string]any

func (m OpenIDWalletProviderMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := verifyRequiredClaims(m, "vp_formats_supported"); err != nil {
		return err
	}
	if err := verifyObjectClaim(m, "vp_formats_supported"); err != nil {
		return err
	}
	if err := verifyNonEmptyStringArrayClaim(m, "client_id_prefixes_supported"); err != nil {
		return err
	}
	return nil
}
