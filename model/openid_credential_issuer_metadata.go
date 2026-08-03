package model

var (
	_ EntityTypeIdentifier = OpenIDCredentialIssuerMetadata{}
)

type OpenIDCredentialIssuerMetadata map[string]any

func (m OpenIDCredentialIssuerMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyRequiredClaims(m,
		"credential_issuer",
		"credential_endpoint",
		"credential_configurations_supported",
	); err != nil {
		return err
	}
	if err := verifyHTTPSURLValue("credential_issuer", m["credential_issuer"], false); err != nil {
		return err
	}
	if err := verifyHTTPSURLValue("credential_endpoint", m["credential_endpoint"], true); err != nil {
		return err
	}
	if err := VerifyObjectClaim(m, "credential_configurations_supported"); err != nil {
		return err
	}
	for _, key := range []string{
		"nonce_endpoint",
		"deferred_credential_endpoint",
		"notification_endpoint",
	} {
		if err := VerifyHTTPSURLClaim(m, key, true); err != nil {
			return err
		}
	}
	if err := VerifyStringArrayClaim(m, "authorization_servers"); err != nil {
		return err
	}
	return nil
}
