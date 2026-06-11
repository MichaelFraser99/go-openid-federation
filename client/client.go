package client

import (
	"context"
	"fmt"

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

	return trust_chain.BuildTrustChain(ctx, c.cfg.Configuration, *parsedLeafEntityIdentifier, *parsedTargetEntityIdentifier)
}

func (c *Client) ResolveMetadata(ctx context.Context, subject string, trustChain []string) (*model.Metadata, error) {
	parsedSubject, err := model.ValidateEntityIdentifier(subject)
	if err != nil {
		return nil, fmt.Errorf("invalid subject entity identifier: %s", err.Error())
	}

	resolved, err := trust_chain.ResolveMetadata(ctx, c.cfg.Configuration, *parsedSubject, trustChain)
	if err != nil {
		return nil, err
	}
	return resolved.Metadata, nil
}
