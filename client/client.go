package client

import (
	"context"
	"fmt"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_chain"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

//todo: jwks, jwks_uri, signed_jwks_uri - see fed spec and ensure the keys are the same if multiple present

//todo: revisit error types in this module

type Client struct {
	cfg model.ClientConfiguration
}

func New(cfg model.ClientConfiguration) *Client {
	return &Client{
		cfg: cfg,
	}
}

// BuildTrustChain takes in a given leaf and trust anchor Entity Identifier pair and then attempts to construct a Trust Chain for the given values
func (c *Client) BuildTrustChain(ctx context.Context, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier string) (parsedSignedTrustChain []string, parsedTrustChain []model.EntityStatement, expiry *int64, err error) {
	parsedLeafEntityIdentifier, err := model.ValidateEntityIdentifier(targetLeafEntityIdentifier)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid target leaf entity identifier: %s", err.Error())
	}
	parsedTargetEntityIdentifier, err := model.ValidateEntityIdentifier(targetTrustAnchorEntityIdentifier)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid target trust anchor entity identifier: %s", err.Error())
	}

	return trust_chain.BuildTrustChain(ctx, c.cfg.Configuration, *parsedLeafEntityIdentifier, *parsedTargetEntityIdentifier, resolvecache.New())
}

func (c *Client) ResolveMetadata(ctx context.Context, subject, trustAnchor string, trustChain []string) (*model.Metadata, error) {
	parsedSubject, err := model.ValidateEntityIdentifier(subject)
	if err != nil {
		return nil, fmt.Errorf("invalid subject entity identifier: %s", err.Error())
	}
	if trustAnchor == "" {
		return nil, model.NewInvalidRequestError("a trust anchor must be named to resolve a trust chain")
	}
	parsedTrustAnchor, err := model.ValidateEntityIdentifier(trustAnchor)
	if err != nil {
		return nil, model.NewInvalidRequestError(fmt.Sprintf("invalid trust anchor entity identifier: %s", err.Error()))
	}

	if *parsedSubject == *parsedTrustAnchor {
		return nil, model.NewInvalidRequestError("the subject must not be the trust anchor it is resolved against")
	}

	resolved, err := trust_chain.ResolveMetadata(ctx, c.cfg.Configuration, *parsedSubject, *parsedTrustAnchor, trustChain, resolvecache.New())
	if err != nil {
		return nil, err
	}
	if resolved.Sub != *parsedSubject {
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("provided trust chain resolves metadata for %s, not the requested subject %s", resolved.Sub, *parsedSubject))
	}
	return resolved.Metadata, nil
}
