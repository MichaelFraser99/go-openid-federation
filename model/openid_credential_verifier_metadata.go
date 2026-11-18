package model

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

var (
	_ entityTypeIdentifier = OpenIDCredentialVerifierMetadata{}
)

type OpenIDCredentialVerifierMetadata map[string]any

func (m OpenIDCredentialVerifierMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	if err := VerifyObjectClaim(m, "vp_formats_supported"); err != nil {
		return err
	}
	for _, key := range []string{
		"redirect_uris",
		"request_uris",
		"response_uris",
	} {
		if err := verifyNonEmptyHTTPSURLArrayClaim(m, key); err != nil {
			return err
		}
	}
	redirectURIs, _ := MetadataStringSlice(m["redirect_uris"])
	if slices.ContainsFunc(redirectURIs, func(redirectURI string) bool { return strings.Contains(redirectURI, "#") }) {
		return fmt.Errorf("'redirect_uris' must not contain a fragment component")
	}
	if err := verifyNonEmptyObjectArrayClaim(m, "dcql_queries"); err != nil {
		return err
	}
	if err := verifyNonEmptyEntityIdentifierArrayClaim(m, "credential_verifier_providers"); err != nil {
		return err
	}
	if err := VerifyJWKSetClaims(m); err != nil {
		return err
	}
	return verifyKeyIDsIdentifyEachKey(m)
}

func verifyKeyIDsIdentifyEachKey(m map[string]any) error {
	jwks, _ := m["jwks"].(map[string]any)
	entries, _ := jwks["keys"].([]any)
	keysByID := map[string]any{}
	for i, entry := range entries {
		key, _ := entry.(map[string]any)
		kid, present := key["kid"]
		if !present {
			return fmt.Errorf("'jwks' has an entry at position %d of 'keys' with no 'kid' member, which Wallet Architectures draft 06 section 6.4.1 requires of every key in the set", i)
		}
		sKid, ok := kid.(string)
		if !ok {
			return fmt.Errorf("'jwks' has an entry at position %d of 'keys' with a malformed 'kid' member", i)
		}
		if previous, seen := keysByID[sKid]; seen && !reflect.DeepEqual(previous, key) {
			return fmt.Errorf("'jwks' has two different entries in 'keys' with the same 'kid', which Wallet Architectures draft 06 section 6.4.1 forbids")
		}
		keysByID[sKid] = key
	}
	return nil
}

func (m OpenIDCredentialVerifierMetadata) VerifyResolvedMetadata() error {
	return VerifyRequiredClaims(m, "vp_formats_supported")
}
