package model

var (
	_ entityTypeIdentifier = OpenIDCredentialVerifierProviderMetadata{}
)

type OpenIDCredentialVerifierProviderMetadata map[string]any

func (m OpenIDCredentialVerifierProviderMetadata) VerifyMetadata() error {
	return VerifyJWKSetClaims(m)
}

func (m OpenIDCredentialVerifierProviderMetadata) VerifyResolvedMetadata() error {
	return VerifyRequiredClaims(m, "jwks")
}
