package model

var (
	_ EntityTypeIdentifier = OpenIDWalletProviderMetadata{}
)

type OpenIDWalletProviderMetadata map[string]any

func (m OpenIDWalletProviderMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyRequiredClaims(m, "vp_formats_supported"); err != nil {
		return err
	}
	if err := VerifyObjectClaim(m, "vp_formats_supported"); err != nil {
		return err
	}
	if err := VerifyNonEmptyStringArrayClaim(m, "client_id_prefixes_supported"); err != nil {
		return err
	}
	return nil
}
