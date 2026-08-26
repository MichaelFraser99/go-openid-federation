package model

import (
	"context"
	"fmt"
)

type EntityIdentifierParam string

const (
	EntityIdentifierParamSub         EntityIdentifierParam = "sub"
	EntityIdentifierParamTrustAnchor EntityIdentifierParam = "trust_anchor"
)

type EntityIdentifierResolver interface {
	ResolveEntityIdentifier(ctx context.Context, param EntityIdentifierParam, raw string) (*EntityIdentifier, error)
}

type StandardEntityIdentifierResolver struct{}

func (StandardEntityIdentifierResolver) ResolveEntityIdentifier(_ context.Context, param EntityIdentifierParam, raw string) (*EntityIdentifier, error) {
	identifier, err := ValidateEntityIdentifier(raw)
	if err != nil {
		return nil, NewInvalidRequestError(fmt.Sprintf("malformed '%s' parameter", param))
	}
	return identifier, nil
}
