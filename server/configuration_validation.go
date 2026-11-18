package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func validateConfiguration(cfg model.ServerConfiguration) error {
	var faults []error
	fault := func(format string, args ...any) {
		faults = append(faults, fmt.Errorf(format, args...))
	}

	if cfg.EntityIdentifier != "" {
		if _, err := model.ValidateEntityIdentifier(string(cfg.EntityIdentifier)); err != nil {
			fault("EntityIdentifier is not valid: %s", err.Error())
		}
	}
	if cfg.SignerConfiguration.Signer == nil {
		fault("SignerConfiguration.Signer is nil")
	}
	if cfg.SignerConfiguration.KeyID == "" {
		fault("SignerConfiguration.KeyID is empty")
	}
	if err := model.VerifyIssuanceAlgorithm(cfg.SignerConfiguration.Algorithm); err != nil {
		fault("SignerConfiguration.Algorithm cannot be used: %s", err.Error())
	}
	if err := cfg.VerifySigningAlgorithms(); err != nil {
		fault("Configuration.SigningAlgorithms cannot be used: %s", err.Error())
	}
	if _, err := model.ResolveStatementLifetime("EntityConfigurationLifetime", cfg.EntityConfigurationLifetime, model.DefaultEntityConfigurationLifetime); err != nil {
		faults = append(faults, err)
	}
	if cfg.IntermediateConfiguration != nil {
		if _, err := model.ResolveStatementLifetime("IntermediateConfiguration.SubordinateStatementLifetime", cfg.IntermediateConfiguration.SubordinateStatementLifetime, model.DefaultSubordinateStatementLifetime); err != nil {
			faults = append(faults, err)
		}
	}
	for i, hint := range cfg.AuthorityHints {
		if _, err := model.ValidateEntityIdentifier(string(hint)); err != nil {
			fault("AuthorityHints[%d] is not an entity identifier: %s", i, err.Error())
		}
	}
	for _, trustMarkType := range slices.Sorted(maps.Keys(cfg.EntityConfiguration.TrustMarkOwners)) {
		owner := cfg.EntityConfiguration.TrustMarkOwners[trustMarkType]
		if owner.Sub == "" {
			fault("EntityConfiguration.TrustMarkOwners[%q].Sub is empty", model.TruncateForResponse(trustMarkType))
		} else if _, err := model.ValidateEntityIdentifier(string(owner.Sub)); err != nil {
			fault("EntityConfiguration.TrustMarkOwners[%q].Sub is not an entity identifier: %s", model.TruncateForResponse(trustMarkType), err.Error())
		}
		if !slices.ContainsFunc(owner.JWKs.Keys, func(key map[string]any) bool {
			return model.ValidateJWKShape(key) == nil && entity_statement.VerifyKeyUse(key) == nil
		}) {
			fault("EntityConfiguration.TrustMarkOwners[%q].JWKs holds no usable key", model.TruncateForResponse(trustMarkType))
		}
	}
	for _, trustMarkType := range slices.Sorted(maps.Keys(cfg.EntityConfiguration.TrustMarkIssuers)) {
		for i, issuer := range cfg.EntityConfiguration.TrustMarkIssuers[trustMarkType] {
			if _, err := model.ValidateEntityIdentifier(string(issuer)); err != nil {
				fault("EntityConfiguration.TrustMarkIssuers[%q][%d] is not an entity identifier: %s", model.TruncateForResponse(trustMarkType), i, err.Error())
			}
		}
	}
	if metadata := cfg.EntityConfiguration.Metadata; metadata != nil {
		raw, err := json.Marshal(metadata)
		if err != nil {
			fault("EntityConfiguration.Metadata cannot be written: %s", err.Error())
		} else if published, err := publishedMetadata(raw); err != nil {
			fault("EntityConfiguration.Metadata is not valid: %s", err.Error())
		} else if err := published.Verify(cfg.EntityTypes, false); err != nil {
			fault("EntityConfiguration.Metadata is not valid: %s", err.Error())
		}
	}
	return errors.Join(faults...)
}

func publishedMetadata(raw []byte) (*model.Metadata, error) {
	var published model.Metadata
	if err := json.Unmarshal(raw, &published); err != nil {
		return nil, err
	}
	return &published, nil
}

func reportIncompleteTrustAnchorMetadata(cfg model.ServerConfiguration) {
	if len(cfg.AuthorityHints) > 0 || cfg.EntityConfiguration.Metadata == nil || cfg.EntityIdentifier == "" {
		return
	}
	raw, err := json.Marshal(cfg.EntityConfiguration.Metadata)
	if err != nil {
		return
	}
	published, err := publishedMetadata(raw)
	if err != nil {
		return
	}
	if err := published.VerifyResolved(cfg.EntityTypes, cfg.EntityIdentifier); err != nil {
		cfg.LogError(context.Background(), "this trust anchor's own metadata does not pass the checks applied to resolved metadata, so resolving it as a subject answers invalid_metadata", slog.String("error", err.Error()))
	}
}
