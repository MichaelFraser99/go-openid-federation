package trust_chain

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func BuildTrustChain(ctx context.Context, cfg model.Configuration, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier model.EntityIdentifier) (trustChain []string, parsedTrustChain []model.EntityStatement, expiry *int64, err error) {
	cfg.LogInfo(ctx, "building chain between entities", slog.String("leaf", string(targetLeafEntityIdentifier)), slog.String("trust_anchor", string(targetTrustAnchorEntityIdentifier)))
	if targetLeafEntityIdentifier == targetTrustAnchorEntityIdentifier {
		return nil, nil, nil, fmt.Errorf("target leaf entity identifier must not match target trust anchor entity identifier")
	}

	signedRoute, route, err := ChainUpOne(ctx, cfg, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier, []model.EntityIdentifier{}, []model.EntityStatement{}, []string{})
	if err != nil {
		return nil, nil, nil, err
	}

	trustChain = []string{signedRoute[0]}
	parsedTrustChain = []model.EntityStatement{route[0]}

	exp := model.CalculateChainExpiration(route)
	if time.Now().UTC().Equal(time.Unix(exp, 0).UTC()) || time.Now().UTC().After(time.Unix(exp, 0).UTC()) {
		return nil, nil, nil, fmt.Errorf("trust chain expired")
	}

	for i := 0; i < len(route)-1; i++ {
		signedResponse, subordinateStatement, err := subordinate_statement.Retrieve(ctx, cfg, route[i+1], route[i].Sub)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to retrieve subordinate statement: %s", err.Error())
		}
		trustChain = append(trustChain, *signedResponse)
		parsedTrustChain = append(parsedTrustChain, *subordinateStatement)
	}

	return append(trustChain, signedRoute[len(signedRoute)-1]), append(parsedTrustChain, route[len(route)-1]), &exp, nil
}

func ChainUpOne(ctx context.Context, cfg model.Configuration, subject, target model.EntityIdentifier, checked []model.EntityIdentifier, path []model.EntityStatement, signedPath []string) ([]string, []model.EntityStatement, error) {
	cfg.LogInfo(ctx, "walking trust chain", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))

	signedSubjectEntityStatement, subjectEntityStatement, err := entity_configuration.Retrieve(ctx, cfg, subject)
	if err != nil {
		cfg.LogInfo(ctx, "failed to retrieve leaf entity configuration", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("error", err.Error()))
		return signedPath, path, model.NewNotFoundError(fmt.Sprintf("failed to retrieve leaf entity configuration: %s", subject))
	}

	path = append(path, *subjectEntityStatement)
	signedPath = append(signedPath, *signedSubjectEntityStatement)
	checked = append(checked, subject)

	if subjectEntityStatement.Iss == target {
		cfg.LogInfo(ctx, "found target entity in trust chain", slog.String("subject", string(subject)), slog.String("target", string(target)))
		return signedPath, path, nil
	}

	cfg.LogInfo(ctx, "evaluating chain options", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path))
	var toCheck []model.EntityIdentifier
	for _, trustIssuer := range subjectEntityStatement.AuthorityHints {
		if trustIssuer == target {
			cfg.LogInfo(ctx, "found target entity in authority hints", slog.String("subject", string(subject)), slog.String("target", string(target)))
			toCheck = []model.EntityIdentifier{trustIssuer}
			break
		} else if !slices.Contains(checked, trustIssuer) {
			toCheck = append(toCheck, trustIssuer)
		}
	}
	cfg.LogInfo(ctx, "checking authority hints", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("authority_hints_checked", checked), slog.Any("authority_hints_to_check", toCheck))

	if len(toCheck) == 0 {
		cfg.LogInfo(ctx, "dead end in path traversal - no paths to check", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))
		return signedPath[:len(signedPath)-1], path[:len(path)-1], model.NewInvalidTrustAnchorError("unable to build trust chain from specified 'sub' to specified 'trust_anchor'")
	}

	for _, trustIssuer := range toCheck {
		cfg.LogInfo(ctx, "checking authority hint", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("authority_hint", string(trustIssuer)))
		signedPath, path, err = ChainUpOne(ctx, cfg, trustIssuer, target, checked, path, signedPath)
		if err == nil {
			return signedPath, path, nil
		}
	}
	cfg.LogInfo(ctx, "dead end in path traversal - all options checked", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))
	return signedPath[:len(signedPath)-1], path[:len(path)-1], model.NewInvalidTrustAnchorError("unable to build trust chain from specified 'sub' to specified 'trust_anchor'")
}

func ResolveMetadata(ctx context.Context, cfg model.Configuration, issuerEntityIdentifier model.EntityIdentifier, trustChain []string) (*model.ResolveResponse, error) {
	cfg.LogInfo(ctx, "resolving metadata from trust chain", slog.String("issuer", string(issuerEntityIdentifier)), slog.Int("chain_length", len(trustChain)))

	if len(trustChain) == 0 {
		cfg.LogInfo(ctx, "trust chain validation failed: empty chain", slog.String("issuer", string(issuerEntityIdentifier)))
		return nil, fmt.Errorf("trust chain must have at least 1 entry")
	}

	_, sub, iss, err := entity_statement.ExtractDetails(trustChain[len(trustChain)-1])
	if err != nil {
		cfg.LogInfo(ctx, "failed to extract details from final chain entry", slog.String("error", err.Error()))
		return nil, fmt.Errorf("final entry in chain malformed: %s", err.Error())
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
		response, err := entity_configuration.Validate(ctx, *parsedSub, trustChain[len(trustChain)-1])
		if err != nil {
			cfg.LogInfo(ctx, "failed to validate self-signed entity configuration", slog.String("entity", string(*parsedSub)), slog.String("error", err.Error()))
			return nil, fmt.Errorf("error validating entity configuration in final chain entry: %s", err.Error())
		}
		processedChain = append(processedChain, *response)
	} else {
		cfg.LogInfo(ctx, "retrieving subject entity configuration", slog.String("subject", string(*parsedSub)))
		signedEntityConfiguration, entityConfiguration, err := entity_configuration.Retrieve(ctx, cfg, *parsedSub)
		if err != nil {
			cfg.LogInfo(ctx, "failed to retrieve subject entity configuration", slog.String("subject", string(*parsedSub)), slog.String("error", err.Error()))
			return nil, err
		}
		trustChain = append(trustChain, *signedEntityConfiguration)
		processedChain = append(processedChain, *entityConfiguration)
	}

	if len(trustChain) == 1 {
		cfg.LogInfo(ctx, "trust chain has single entry, returning metadata directly", slog.String("subject", string(processedChain[0].Sub)), slog.Int("trust_marks_count", len(processedChain[0].TrustMarks)))
		return &model.ResolveResponse{
			Iss:        issuerEntityIdentifier,
			Sub:        processedChain[0].Sub,
			Iat:        time.Now().UTC().Unix(),
			Exp:        processedChain[0].Exp,
			TrustChain: trustChain,
			Metadata:   processedChain[0].Metadata,
			TrustMarks: processedChain[0].TrustMarks,
		}, nil
	}

	cfg.LogInfo(ctx, "processing multi-level trust chain", slog.Int("chain_length", len(trustChain)))

	for i := len(trustChain) - 2; i >= 1; i-- {
		previousStatement := processedChain[len(trustChain)-(i+2)]

		cfg.LogInfo(ctx, "validating chain step", slog.Int("step", i), slog.String("issuer", string(previousStatement.Iss)))
		nextStep, err := subordinate_statement.Validate(previousStatement, trustChain[i])
		if err != nil {
			cfg.LogInfo(ctx, "failed to validate chain step", slog.Int("step", i), slog.String("error", err.Error()))
			return nil, fmt.Errorf("error validating step in provided trust chain: %s", err.Error())
		}
		processedChain = append(processedChain, *nextStep)
	}

	cfg.LogInfo(ctx, "validating subject entity configuration", slog.String("subject", string(processedChain[len(processedChain)-1].Sub)))
	subjectEntityConfiguration, err := entity_configuration.Validate(ctx, processedChain[len(processedChain)-1].Sub, trustChain[0])
	if err != nil {
		cfg.LogInfo(ctx, "failed to validate subject entity configuration", slog.String("error", err.Error()))
		return nil, fmt.Errorf("error parsing trust chain subject entity configuration: %s", err.Error())
	}
	processedChain = append(processedChain, *subjectEntityConfiguration)

	slices.Reverse(processedChain)
	cfg.LogInfo(ctx, "chain processing completed, reversed chain", slog.Int("chain_length", len(processedChain)))

	subjectKid, _, _, err := entity_statement.ExtractDetails(trustChain[0])
	if err != nil {
		cfg.LogInfo(ctx, "failed to extract subject kid", slog.String("error", err.Error()))
		return nil, fmt.Errorf("subject entry in chain malformed: %s", err.Error())
	}

	cfg.LogInfo(ctx, "verifying subject key in subordinate statement", slog.String("kid", *subjectKid))
	found := false
	for _, issuerKey := range processedChain[1].JWKs.Keys {
		if issuerKid, ok := issuerKey["kid"]; !ok {
			cfg.LogInfo(ctx, "subordinate statement contains key without kid claim")
			return nil, fmt.Errorf("one or more keys in trust chain missing required 'kid' claim")
		} else if issuerKid == *subjectKid {
			found = true
			break
		}
	}
	if !found {
		cfg.LogInfo(ctx, "subject key not found in subordinate statement", slog.String("kid", *subjectKid))
		return nil, fmt.Errorf("subordinate statment for subject entity does not contain the key used to sign the subject entity's Entity Configuration")
	}
	cfg.LogInfo(ctx, "subject key verified in subordinate statement", slog.String("kid", *subjectKid))

	exp := model.CalculateChainExpiration(processedChain)
	cfg.LogInfo(ctx, "checking chain expiration", slog.Int64("exp", exp), slog.Int64("now", time.Now().UTC().Unix()))
	if time.Now().UTC().Equal(time.Unix(exp, 0)) || time.Now().UTC().After(time.Unix(exp, 0)) {
		cfg.LogInfo(ctx, "trust chain has expired", slog.Int64("exp", exp))
		return nil, fmt.Errorf("trust chain expired")
	}

	result := &model.ResolveResponse{
		Iss:        issuerEntityIdentifier,
		Sub:        processedChain[0].Sub,
		Iat:        time.Now().UTC().Unix(),
		Exp:        exp,
		TrustChain: trustChain,
	}

	cfg.LogInfo(ctx, "processing and extracting metadata policy from chain", slog.Int("chain_length", len(processedChain)))
	finalisedPolicy, err := model.ProcessAndExtractPolicy(processedChain)
	if err != nil {
		cfg.LogInfo(ctx, "failed to process and extract policy", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to process and extract policy: %s", err.Error())
	}

	if finalisedPolicy == nil {
		cfg.LogInfo(ctx, "no policy to apply, returning metadata directly", slog.String("subject", string(processedChain[0].Sub)), slog.Int("trust_marks_count", len(processedChain[0].TrustMarks)))
		result.Metadata = processedChain[0].Metadata
		result.TrustMarks = processedChain[0].TrustMarks
		return result, nil
	}

	cfg.LogInfo(ctx, "applying policy to subject metadata", slog.String("subject", string(processedChain[0].Sub)))
	applied, err := model.ApplyPolicy(processedChain[0], *finalisedPolicy)
	if err != nil {
		cfg.LogInfo(ctx, "failed to apply policy", slog.Any("metadata", processedChain[0]), slog.Any("policy", *finalisedPolicy), slog.String("error", err.Error()))
		return nil, model.NewInvalidMetadataError("unresolvable metadata policy encountered")
	}
	result.Metadata = applied.Metadata
	result.TrustMarks = processedChain[0].TrustMarks

	cfg.LogInfo(ctx, "metadata resolution completed successfully", slog.String("subject", string(result.Sub)), slog.Int("trust_marks_count", len(result.TrustMarks)), slog.Int64("exp", result.Exp))
	return result, nil
}
