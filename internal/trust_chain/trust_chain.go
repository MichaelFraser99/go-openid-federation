package trust_chain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func BuildTrustChain(ctx context.Context, cfg model.Configuration, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier model.EntityIdentifier, cache *resolvecache.Cache) (trustChain []string, parsedTrustChain []model.EntityStatement, expiry *int64, err error) {
	cfg.LogInfo(ctx, "building chain between entities", slog.String("leaf", string(targetLeafEntityIdentifier)), slog.String("trust_anchor", string(targetTrustAnchorEntityIdentifier)))
	if targetLeafEntityIdentifier == targetTrustAnchorEntityIdentifier {
		return nil, nil, nil, fmt.Errorf("target leaf entity identifier must not match target trust anchor entity identifier")
	}

	signedRoute, route, _, err := ChainUpOne(ctx, cfg, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier, []model.EntityIdentifier{}, []model.EntityStatement{}, []string{}, cache, map[DeadEnd]struct{}{})
	if err != nil {
		return nil, nil, nil, err
	}

	trustChain = []string{signedRoute[0]}
	parsedTrustChain = []model.EntityStatement{route[0]}

	exp := model.CalculateChainExpiration(route)
	if err = model.VerifyChainExpiry(exp); err != nil {
		return nil, nil, nil, err
	}

	for i := 0; i < len(route)-1; i++ {
		signedResponse, subordinateStatement, err := subordinate_statement.Retrieve(ctx, cfg, route[i+1], route[i].Sub)
		if err != nil {
			cfg.LogInfo(ctx, "subordinate statement unusable", slog.String("issuer", string(route[i+1].Sub)), slog.String("subject", string(route[i].Sub)), slog.String("error", model.TruncateForResponse(err.Error())))
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, nil, walkNotCompleted(ctxErr)
			}
			return nil, nil, nil, fmt.Errorf("failed to retrieve subordinate statement: %w", err)
		}
		trustChain = append(trustChain, *signedResponse)
		parsedTrustChain = append(parsedTrustChain, *subordinateStatement)
	}

	trustChain = append(trustChain, signedRoute[len(signedRoute)-1])
	parsedTrustChain = append(parsedTrustChain, route[len(route)-1])

	if len(parsedTrustChain) < 3 {
		return nil, nil, nil, model.NewInvalidTrustChainError("trust chain contains no subordinate statement about the subject")
	}

	if err = verifyChainLinks(ctx, cfg, trustChain, parsedTrustChain); err != nil {
		return nil, nil, nil, err
	}

	return trustChain, parsedTrustChain, &exp, nil
}

func verifyChainLinks(ctx context.Context, cfg model.Configuration, signedChain []string, parsedChain []model.EntityStatement) error {
	for i := 0; i < len(signedChain)-1; i++ {
		kid, _, _, err := entity_statement.ExtractDetails(signedChain[i])
		if err != nil {
			return model.NewInvalidTrustChainError(fmt.Sprintf("entry %d in the trust chain is malformed: %s", i, err.Error()))
		}
		if err = entity_statement.VerifyAgainstJwks(signedChain[i], *kid, parsedChain[i+1].JWKs); err != nil {
			cfg.LogInfo(ctx, "trust chain entry not signed by a key published in the statement above it", slog.Int("entry", i), slog.String("kid", *kid), slog.String("error", err.Error()))
			return model.NewInvalidTrustChainError(fmt.Sprintf("entry %d in the trust chain is not signed by a key published for it in the statement above it: %s", i, err.Error()))
		}
	}
	return nil
}

func walkNotCompleted(err error) error {
	return fmt.Errorf("%w%s: %w", model.ErrTemporarilyUnavailable, "trust chain walk did not complete", err)
}

type DeadEnd struct {
	Subject   model.EntityIdentifier
	Remaining int
}

func deadEndKey(cfg model.Configuration, subject model.EntityIdentifier, depth int) DeadEnd {
	key := DeadEnd{Subject: subject}
	if cfg.MaxTrustChainDepth > 0 {
		key.Remaining = cfg.MaxTrustChainDepth - depth
	}
	return key
}

func ChainUpOne(ctx context.Context, cfg model.Configuration, subject, target model.EntityIdentifier, checked []model.EntityIdentifier, path []model.EntityStatement, signedPath []string, cache *resolvecache.Cache, deadEnds map[DeadEnd]struct{}) ([]string, []model.EntityStatement, bool, error) {
	cfg.LogInfo(ctx, "walking trust chain", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))

	if err := ctx.Err(); err != nil {
		cfg.LogInfo(ctx, "abandoning trust chain walk", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("error", err.Error()))
		return signedPath, path, false, walkNotCompleted(err)
	}

	if cfg.MaxTrustChainDepth > 0 && len(path) >= cfg.MaxTrustChainDepth {
		cfg.LogInfo(ctx, "reached configured maximum trust chain depth", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Int("max_depth", cfg.MaxTrustChainDepth))
		return signedPath, path, true, model.NewInvalidTrustAnchorError("unable to build trust chain from specified 'sub' to specified 'trust_anchor'")
	}

	subjectKey := deadEndKey(cfg, subject, len(path))
	if _, dead := deadEnds[subjectKey]; dead {
		cfg.LogInfo(ctx, "skipping entity already proven not to reach the trust anchor", slog.String("subject", string(subject)), slog.String("target", string(target)))
		return signedPath, path, false, model.NewInvalidTrustAnchorError("unable to build trust chain from specified 'sub' to specified 'trust_anchor'")
	}

	signedSubjectEntityStatement, subjectEntityStatement, err := entity_configuration.Retrieve(ctx, cfg, subject, cache)
	if err != nil {
		cfg.LogInfo(ctx, "entity configuration unusable", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("error", err.Error()))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return signedPath, path, false, walkNotCompleted(ctxErr)
		}
		deadEnds[subjectKey] = struct{}{}
		if errors.Is(err, model.ErrInvalidMetadata) {
			return signedPath, path, false, model.NewInvalidMetadataError(fmt.Sprintf("entity configuration for %s failed validation", subject))
		}
		if errors.Is(err, model.ErrInvalidTrustChain) {
			return signedPath, path, false, model.NewInvalidTrustChainError(fmt.Sprintf("entity configuration for %s failed validation", subject))
		}
		return signedPath, path, false, model.NewNotFoundError(fmt.Sprintf("failed to retrieve entity configuration for %s", subject))
	}

	path = append(path, *subjectEntityStatement)
	signedPath = append(signedPath, *signedSubjectEntityStatement)
	checked = append(checked, subject)

	if subjectEntityStatement.Iss == target {
		cfg.LogInfo(ctx, "found target entity in trust chain", slog.String("subject", string(subject)), slog.String("target", string(target)))
		return signedPath, path, false, nil
	}

	cfg.LogInfo(ctx, "evaluating chain options", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path))
	tainted := false
	var toCheck []model.EntityIdentifier
	for _, trustIssuer := range subjectEntityStatement.AuthorityHints {
		if trustIssuer == target {
			cfg.LogInfo(ctx, "found target entity in authority hints", slog.String("subject", string(subject)), slog.String("target", string(target)))
			toCheck = []model.EntityIdentifier{trustIssuer}
			break
		} else if slices.Contains(checked, trustIssuer) {
			tainted = true
		} else if _, dead := deadEnds[deadEndKey(cfg, trustIssuer, len(path))]; !dead {
			toCheck = append(toCheck, trustIssuer)
		}
	}
	cfg.LogInfo(ctx, "checking authority hints", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("authority_hints_checked", checked), slog.Any("authority_hints_to_check", toCheck))

	for _, trustIssuer := range toCheck {
		cfg.LogInfo(ctx, "checking authority hint", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("authority_hint", string(trustIssuer)))
		var childTainted bool
		signedPath, path, childTainted, err = ChainUpOne(ctx, cfg, trustIssuer, target, checked, path, signedPath, cache, deadEnds)
		if err == nil {
			return signedPath, path, false, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return signedPath, path, false, walkNotCompleted(ctxErr)
		}
		tainted = tainted || childTainted
	}
	cfg.LogInfo(ctx, "dead end in path traversal", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))
	deadEnds[subjectKey] = struct{}{}
	return signedPath[:len(signedPath)-1], path[:len(path)-1], tainted, model.NewInvalidTrustAnchorError("unable to build trust chain from specified 'sub' to specified 'trust_anchor'")
}

func ResolveMetadata(ctx context.Context, cfg model.Configuration, issuerEntityIdentifier model.EntityIdentifier, trustChain []string, cache *resolvecache.Cache) (*model.ResolveResponse, error) {
	cfg.LogInfo(ctx, "resolving metadata from trust chain", slog.String("issuer", string(issuerEntityIdentifier)), slog.Int("chain_length", len(trustChain)))

	if len(trustChain) == 0 {
		cfg.LogInfo(ctx, "trust chain validation failed: empty chain", slog.String("issuer", string(issuerEntityIdentifier)))
		return nil, model.NewInvalidTrustChainError("trust chain must have at least 1 entry")
	}

	_, sub, iss, err := entity_statement.ExtractDetails(trustChain[len(trustChain)-1])
	if err != nil {
		cfg.LogInfo(ctx, "failed to extract details from final chain entry", slog.String("error", err.Error()))
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("final entry in chain malformed: %s", err.Error()))
	}
	parsedSub, err := model.ValidateEntityIdentifier(*sub)
	if err != nil {
		cfg.LogInfo(ctx, "invalid sub claim in final chain entry", slog.String("sub", *sub), slog.String("error", err.Error()))
		return nil, fmt.Errorf("error validating `sub` claim of final chain entry: %s", err.Error())
	}
	parsedIss, err := model.ValidateEntityIdentifier(*iss)
	if err != nil {
		cfg.LogInfo(ctx, "invalid iss claim in final chain entry", slog.String("iss", *iss), slog.String("error", err.Error()))
		return nil, fmt.Errorf("error validating `iss` claim of final chain entry: %s", err.Error())
	}

	cfg.LogInfo(ctx, "extracted chain endpoints", slog.String("sub", string(*parsedSub)), slog.String("iss", string(*parsedIss)))

	var processedChain []model.EntityStatement

	if *parsedSub == *parsedIss {
		cfg.LogInfo(ctx, "processing self-signed entity configuration", slog.String("entity", string(*parsedSub)))
		response, err := entity_configuration.Validate(ctx, cfg, *parsedSub, trustChain[len(trustChain)-1])
		if err != nil {
			cfg.LogInfo(ctx, "failed to validate self-signed entity configuration", slog.String("entity", string(*parsedSub)), slog.String("error", err.Error()))
			return nil, fmt.Errorf("error validating entity configuration in final chain entry: %w", err)
		}
		processedChain = append(processedChain, *response)
	} else {
		cfg.LogInfo(ctx, "retrieving omitted trust anchor entity configuration", slog.String("trust_anchor", string(*parsedIss)))
		signedEntityConfiguration, entityConfiguration, err := entity_configuration.Retrieve(ctx, cfg, *parsedIss, cache)
		if err != nil {
			cfg.LogInfo(ctx, "failed to retrieve trust anchor entity configuration", slog.String("trust_anchor", string(*parsedIss)), slog.String("error", err.Error()))
			return nil, err
		}
		trustChain = append(trustChain, *signedEntityConfiguration)
		processedChain = append(processedChain, *entityConfiguration)
	}

	if len(trustChain) == 1 {
		cfg.LogInfo(ctx, "trust chain has single entry, returning metadata directly", slog.String("subject", string(processedChain[0].Sub)), slog.Int("trust_marks_count", len(processedChain[0].TrustMarks)))
		singleExp := model.CalculateChainExpiration(processedChain)
		if err := model.VerifyChainExpiry(singleExp); err != nil {
			cfg.LogInfo(ctx, "trust chain expiry unusable", slog.Int64("exp", singleExp), slog.String("error", err.Error()))
			return nil, err
		}
		if processedChain[0].Metadata != nil {
			if err := processedChain[0].Metadata.VerifyResolved(cfg.EntityTypes); err != nil {
				cfg.LogInfo(ctx, "resolved metadata failed verification", slog.String("subject", string(processedChain[0].Sub)), slog.String("error", err.Error()))
				return nil, model.NewInvalidMetadataError(fmt.Sprintf("resolved metadata for %s is invalid: %s", processedChain[0].Sub, err.Error()))
			}
		}
		return &model.ResolveResponse{
			Iss:        issuerEntityIdentifier,
			Sub:        processedChain[0].Sub,
			Iat:        time.Now().UTC().Unix(),
			Exp:        singleExp,
			TrustChain: trustChain,
			Metadata:   processedChain[0].Metadata,
			TrustMarks: processedChain[0].TrustMarks,
		}, nil
	}

	cfg.LogInfo(ctx, "processing multi-level trust chain", slog.Int("chain_length", len(trustChain)))

	for i := len(trustChain) - 2; i >= 1; i-- {
		previousStatement := processedChain[len(trustChain)-(i+2)]

		cfg.LogInfo(ctx, "validating chain step", slog.Int("step", i), slog.String("issuer", string(previousStatement.Iss)))
		nextStep, err := subordinate_statement.Validate(cfg, previousStatement, trustChain[i])
		if err != nil {
			cfg.LogInfo(ctx, "failed to validate chain step", slog.Int("step", i), slog.String("error", err.Error()))
			return nil, fmt.Errorf("%w%s: %w", model.ErrInvalidTrustChain, "error validating step in provided trust chain", err)
		}
		processedChain = append(processedChain, *nextStep)
	}

	immediateSuperiorStatement := processedChain[len(processedChain)-1]
	cfg.LogInfo(ctx, "validating subject entity configuration", slog.String("subject", string(immediateSuperiorStatement.Sub)))
	subjectEntityConfiguration, err := entity_configuration.Validate(ctx, cfg, immediateSuperiorStatement.Sub, trustChain[0])
	if err != nil {
		cfg.LogInfo(ctx, "failed to validate subject entity configuration", slog.String("error", err.Error()))
		return nil, fmt.Errorf("%w%s: %w", model.ErrInvalidTrustChain, "error parsing trust chain subject entity configuration", err)
	}
	if !slices.Contains(subjectEntityConfiguration.AuthorityHints, immediateSuperiorStatement.Iss) {
		cfg.LogInfo(ctx, "subordinate statement issuer is not listed in the subject's authority_hints", slog.String("issuer", string(immediateSuperiorStatement.Iss)), slog.Any("authority_hints", subjectEntityConfiguration.AuthorityHints))
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("subordinate statement issuer %s is not listed in the authority_hints of subject %s", immediateSuperiorStatement.Iss, subjectEntityConfiguration.Sub))
	}

	processedChain = append(processedChain, *subjectEntityConfiguration)

	slices.Reverse(processedChain)
	cfg.LogInfo(ctx, "chain processing completed, reversed chain", slog.Int("chain_length", len(processedChain)))

	subjectKid, _, _, err := entity_statement.ExtractDetails(trustChain[0])
	if err != nil {
		cfg.LogInfo(ctx, "failed to extract subject kid", slog.String("error", err.Error()))
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("subject entry in chain malformed: %s", err.Error()))
	}

	cfg.LogInfo(ctx, "verifying subject entity configuration against the key published by its superior", slog.String("kid", *subjectKid))
	if err = entity_statement.VerifyAgainstJwks(trustChain[0], *subjectKid, processedChain[1].JWKs); err != nil {
		cfg.LogInfo(ctx, "subject entity configuration not signed by a key published for it by its superior", slog.String("kid", *subjectKid), slog.String("error", err.Error()))
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("subject entity configuration is not signed by the key registered for it in the subordinate statement above it: %s", err.Error()))
	}
	cfg.LogInfo(ctx, "subject entity configuration verified against superior's published key", slog.String("kid", *subjectKid))

	exp := model.CalculateChainExpiration(processedChain)
	cfg.LogInfo(ctx, "checking chain expiration", slog.Int64("exp", exp), slog.Int64("now", time.Now().UTC().Unix()))
	if err := model.VerifyChainExpiry(exp); err != nil {
		cfg.LogInfo(ctx, "trust chain expiry unusable", slog.Int64("exp", exp), slog.String("error", err.Error()))
		return nil, err
	}

	result := &model.ResolveResponse{
		Iss:        issuerEntityIdentifier,
		Sub:        processedChain[0].Sub,
		Iat:        time.Now().UTC().Unix(),
		Exp:        exp,
		TrustChain: trustChain,
	}

	if len(processedChain) < 3 {
		cfg.LogInfo(ctx, "trust chain holds no subordinate statement about the subject", slog.Int("chain_length", len(processedChain)))
		return nil, model.NewInvalidTrustChainError("trust chain must hold a subordinate statement about the subject")
	}

	subject := processedChain[0]
	subject.Metadata = model.ApplySuperiorMetadata(processedChain[0].Metadata, processedChain[1].Metadata)
	cfg.LogInfo(ctx, "applied immediate superior supplied metadata", slog.String("subject", string(subject.Sub)), slog.String("superior", string(processedChain[1].Iss)))

	cfg.LogInfo(ctx, "processing and extracting metadata policy from chain", slog.Int("chain_length", len(processedChain)))
	finalisedPolicy, err := model.ProcessAndExtractPolicy(processedChain)
	if err != nil {
		cfg.LogInfo(ctx, "failed to process and extract policy", slog.String("error", err.Error()))
		return nil, model.NewInvalidMetadataError(fmt.Sprintf("metadata policy for %s is unresolvable: %s", subject.Sub, err.Error()))
	}

	if finalisedPolicy == nil {
		cfg.LogInfo(ctx, "no policy to apply, returning metadata directly", slog.String("subject", string(subject.Sub)), slog.Int("trust_marks_count", len(subject.TrustMarks)))
		if subject.Metadata != nil {
			if err := subject.Metadata.VerifyResolved(cfg.EntityTypes); err != nil {
				cfg.LogInfo(ctx, "resolved metadata failed verification", slog.String("subject", string(subject.Sub)), slog.String("error", err.Error()))
				return nil, model.NewInvalidMetadataError(fmt.Sprintf("resolved metadata for %s is invalid: %s", subject.Sub, err.Error()))
			}
		}
		result.Metadata = subject.Metadata
		result.TrustMarks = subject.TrustMarks
		return result, nil
	}

	cfg.LogInfo(ctx, "applying policy to subject metadata", slog.String("subject", string(subject.Sub)))
	applied, err := model.ApplyPolicy(subject, *finalisedPolicy)
	if err != nil {
		cfg.LogInfo(ctx, "failed to apply policy", slog.Any("metadata", subject), slog.Any("policy", *finalisedPolicy), slog.String("error", err.Error()))
		return nil, model.NewInvalidMetadataError(fmt.Sprintf("metadata policy for %s is unresolvable", subject.Sub))
	}

	if applied.Metadata != nil {
		if err = applied.Metadata.VerifyResolved(cfg.EntityTypes); err != nil {
			cfg.LogInfo(ctx, "resolved metadata failed verification", slog.String("subject", string(subject.Sub)), slog.String("error", err.Error()))
			return nil, model.NewInvalidMetadataError(fmt.Sprintf("resolved metadata for %s is invalid: %s", subject.Sub, err.Error()))
		}
	}

	result.Metadata = applied.Metadata
	result.TrustMarks = subject.TrustMarks

	cfg.LogInfo(ctx, "metadata resolution completed successfully", slog.String("subject", string(result.Sub)), slog.Int("trust_marks_count", len(result.TrustMarks)), slog.Int64("exp", result.Exp))
	return result, nil
}
