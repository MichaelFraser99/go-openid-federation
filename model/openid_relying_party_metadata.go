package model

import (
	"fmt"
)

var (
	_ EntityTypeIdentifier = OpenIDRelyingPartyMetadata{}
)

type OpenIDRelyingPartyMetadata map[string]any

func (m OpenIDRelyingPartyMetadata) VerifyMetadata() error {
	if len(m) == 0 { //explicitly ignoring constraints on empty JSON ({})
		return nil
	}
	for _, k := range []string{
		"redirect_uris",
		"client_registration_types",
	} {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing required '%s' claim", k)
		}
	}
	return nil
}
