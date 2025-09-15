package trust_chain

import (
	"context"
	"fmt"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"log/slog"
	"net/http"
	"slices"
	"time"
)

func BuildTrustChain(ctx context.Context, l *slog.Logger, httpClient *http.Client, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier model.EntityIdentifier) (trustChain []string, parsedTrustChain []model.EntityStatement, expiry *int64, err error) {
	logging.LogInfo(l, ctx, "building chain between entities", slog.String("leaf", string(targetLeafEntityIdentifier)), slog.String("trust_anchor", string(targetTrustAnchorEntityIdentifier)))
	if targetLeafEntityIdentifier == targetTrustAnchorEntityIdentifier {
		return nil, nil, nil, fmt.Errorf("target leaf entity identifier must not match target trust anchor entity identifier")
	}

	signedRoute, route, err := ChainUpOne(ctx, l, httpClient, targetLeafEntityIdentifier, targetTrustAnchorEntityIdentifier, []model.EntityIdentifier{}, []model.EntityStatement{}, []string{})
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
		signedResponse, subordinateStatement, err := subordinate_statement.Retrieve(httpClient, route[i+1], route[i].Sub)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to retrieve subordinate statement: %s", err.Error())
		}
		trustChain = append(trustChain, *signedResponse)
		parsedTrustChain = append(parsedTrustChain, *subordinateStatement)
	}

	return append(trustChain, signedRoute[len(signedRoute)-1]), append(parsedTrustChain, route[len(route)-1]), &exp, nil
}

func ChainUpOne(ctx context.Context, l *slog.Logger, httpClient *http.Client, subject, target model.EntityIdentifier, checked []model.EntityIdentifier, path []model.EntityStatement, signedPath []string) ([]string, []model.EntityStatement, error) {
	logging.LogInfo(l, ctx, "walking trust chain", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))

	signedSubjectEntityStatement, subjectEntityStatement, err := entity_configuration.Retrieve(httpClient, subject)
	if err != nil {
		logging.LogInfo(l, ctx, "failed to retrieve leaf entity configuration", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("error", err.Error()))
		return signedPath, path, fmt.Errorf("failed to retrieve leaf entity configuration: %s", err.Error())
	}

	path = append(path, *subjectEntityStatement)
	signedPath = append(signedPath, *signedSubjectEntityStatement)
	checked = append(checked, subject)

	if subjectEntityStatement.Iss == target {
		logging.LogInfo(l, ctx, "found target entity in trust chain", slog.String("subject", string(subject)), slog.String("target", string(target)))
		return signedPath, path, nil
	}

	var toCheck []model.EntityIdentifier
	for _, trustIssuer := range subjectEntityStatement.AuthorityHints {
		if trustIssuer == target {
			logging.LogInfo(l, ctx, "found target entity in authority hints", slog.String("subject", string(subject)), slog.String("target", string(target)))
			toCheck = []model.EntityIdentifier{trustIssuer}
			break
		} else if !slices.Contains(checked, trustIssuer) {
			toCheck = append(toCheck, trustIssuer)
		}
	}
	logging.LogInfo(l, ctx, "checking authority hints", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("authority_hints_checked", checked), slog.Any("authority_hints_to_check", toCheck))

	if len(toCheck) == 0 {
		logging.LogInfo(l, ctx, "dead end in path traversal - no paths to check", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))
		return signedPath[:len(signedPath)-1], path[:len(path)-1], fmt.Errorf("no path to target entity found")
	}

	for _, trustIssuer := range toCheck {
		logging.LogInfo(l, ctx, "checking authority hint", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.String("authority_hint", string(trustIssuer)))
		signedPath, path, err = ChainUpOne(ctx, l, httpClient, trustIssuer, target, checked, path, signedPath)
		if err == nil {
			return signedPath, path, nil
		}
	}
	logging.LogInfo(l, ctx, "dead end in path traversal - all options checked", slog.String("subject", string(subject)), slog.String("target", string(target)), slog.Any("checked", checked), slog.Any("path", path), slog.Any("signed_path", signedPath))
	return signedPath[:len(signedPath)-1], path[:len(path)-1], fmt.Errorf("no path to target entity found")
}

func ResolveMetadata(issuerEntityIdentifier model.EntityIdentifier, trustChain []string) (*model.ResolveResponse, error) {
	if len(trustChain) == 0 {
		return nil, fmt.Errorf("trust chain must have at least 1 entry")
	}

	_, sub, iss, err := entity_statement.ExtractDetails(trustChain[len(trustChain)-1])
	if err != nil {
		return nil, fmt.Errorf("final entry in chain malformed: %s", err.Error())
	}
	parsedSub, err := model.ValidateEntityIdentifier(*sub)
	if err != nil {
		return nil, fmt.Errorf("error validating `sub` claim of final chain entry: %s", err.Error())
	}
	parsedIss, err := model.ValidateEntityIdentifier(*iss)
	if err != nil {
		return nil, fmt.Errorf("error validating `iss` claim of final chain entry: %s", err.Error())
	}

	var processedChain []model.EntityStatement

	if *parsedSub == *parsedIss {
		response, err := entity_configuration.Validate(*parsedSub, trustChain[len(trustChain)-1])
		if err != nil {
			return nil, fmt.Errorf("error validating entity configuration in final chain entry: %s", err.Error())
		}
		processedChain = append(processedChain, *response)
	} else {
		signedEntityConfiguration, entityConfiguration, err := entity_configuration.Retrieve(http.DefaultClient, *parsedSub) //todo: pass in http client instead
		if err != nil {
			return nil, err
		}
		trustChain = append(trustChain, *signedEntityConfiguration)
		processedChain = append(processedChain, *entityConfiguration)
	}

	if len(trustChain) == 1 {
		return &model.ResolveResponse{
			Iss:        issuerEntityIdentifier,
			Sub:        processedChain[0].Sub,
			Iat:        time.Now().UTC().Unix(),
			Exp:        processedChain[0].Exp,
			TrustChain: trustChain,
			Metadata:   processedChain[0].Metadata,
		}, nil
	}

	for i := len(trustChain) - 2; i >= 1; i-- {
		previousStatement := processedChain[len(trustChain)-(i+2)]

		nextStep, err := subordinate_statement.Validate(previousStatement, trustChain[i])
		if err != nil {
			return nil, fmt.Errorf("error validating step in provided trust chain: %s", err.Error())
		}
		processedChain = append(processedChain, *nextStep)
	}

	subjectEntityConfiguration, err := entity_configuration.Validate(processedChain[len(processedChain)-1].Sub, trustChain[0])
	if err != nil {
		return nil, fmt.Errorf("error parsing trust chain subject entity configuration: %s", err.Error())
	}
	processedChain = append(processedChain, *subjectEntityConfiguration)

	slices.Reverse(processedChain)

	subjectKid, _, _, err := entity_statement.ExtractDetails(trustChain[0])
	if err != nil {
		return nil, fmt.Errorf("subject entry in chain malformed: %s", err.Error())
	}

	found := false
	for _, issuerKey := range processedChain[1].JWKs.Keys {
		if issuerKid, ok := issuerKey["kid"]; !ok {
			return nil, fmt.Errorf("one or more keys in trust chain missing required 'kid' claim")
		} else if issuerKid == *subjectKid {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("subordinate statment for subject entity does not contain the key used to sign the subject entity's Entity Configuration")
	}

	exp := model.CalculateChainExpiration(processedChain)
	if time.Now().UTC().Equal(time.Unix(exp, 0)) || time.Now().UTC().After(time.Unix(exp, 0)) {
		return nil, fmt.Errorf("trust chain expired")
	}

	result := &model.ResolveResponse{
		Iss:        issuerEntityIdentifier,
		Sub:        processedChain[0].Sub,
		Iat:        time.Now().UTC().Unix(),
		Exp:        exp,
		TrustChain: trustChain,
	}

	finalisedPolicy, err := model.ProcessAndExtractPolicy(processedChain)
	if err != nil {
		return nil, fmt.Errorf("failed to process and extract policy: %s", err.Error())
	}

	if finalisedPolicy == nil {
		result.Metadata = processedChain[0].Metadata
		return result, nil
	}

	applied, err := model.ApplyPolicy(processedChain[0], *finalisedPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to apply policy: %s", err.Error())
	}
	result.Metadata = applied.Metadata

	return result, nil
}
