package model

import (
	"context"
	"fmt"
)

// EntityIdentifierParam identifies which request parameter an incoming value was
// read from, so an EntityIdentifierResolver can treat parameters differently.
type EntityIdentifierParam string

const (
	EntityIdentifierParamSub         EntityIdentifierParam = "sub"
	EntityIdentifierParamTrustAnchor EntityIdentifierParam = "trust_anchor"
)

// EntityIdentifierResolver turns an incoming, possibly non-standard, request
// value into the canonical Entity Identifier the library operates on. It runs at
// the endpoint boundary before any further processing, letting a consumer map
// non-standard identifiers onto real ones. When a ServerConfiguration provides no
// resolver, StandardEntityIdentifierResolver is used, preserving standard
// behaviour.
type EntityIdentifierResolver interface {
	ResolveEntityIdentifier(ctx context.Context, param EntityIdentifierParam, raw string) (*EntityIdentifier, error)
}

// StandardEntityIdentifierResolver is the default, standards-compliant resolver:
// it validates the incoming value as an Entity Identifier and performs no
// mapping. Custom resolvers may embed it to reuse this validation as a fallback.
type StandardEntityIdentifierResolver struct{}

func (StandardEntityIdentifierResolver) ResolveEntityIdentifier(_ context.Context, param EntityIdentifierParam, raw string) (*EntityIdentifier, error) {
	identifier, err := ValidateEntityIdentifier(raw)
	if err != nil {
		return nil, NewInvalidRequestError(fmt.Sprintf("malformed '%s' parameter", param))
	}
	return identifier, nil
}
