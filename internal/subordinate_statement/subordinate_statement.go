package subordinate_statement

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Retrieve(ctx context.Context, cfg model.Configuration, issuer model.EntityStatement, subject model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	if cfg.HttpClient == nil {
		return nil, nil, model.NewServerError("no http client present")
	}
	if issuer.Iss != issuer.Sub {
		return nil, nil, model.NewServerError("the value of 'issuer' must be an entity configuration")
	}
	if issuer.Metadata == nil || issuer.Metadata.FederationMetadata == nil {
		return nil, nil, model.NewInvalidTrustChainError("issuer entity statement does not list a federation fetch endpoint within it's federation metadata")
	}
	fetchEndpoint, ok := (*issuer.Metadata.FederationMetadata)["federation_fetch_endpoint"].(string)
	if !ok || fetchEndpoint == "" {
		return nil, nil, model.NewInvalidTrustChainError("issuer entity statement does not list a federation fetch endpoint within it's federation metadata")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, cfg.PeerResponseTimeLimit())
	defer cancel()

	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, fmt.Sprintf("%ssub=%s", func() string {
		trimmedString := strings.TrimSuffix(fetchEndpoint, "/")
		if strings.Contains(trimmedString, "?") {
			return trimmedString + "&"
		} else {
			return trimmedString + "?"
		}
	}(), url.QueryEscape(string(subject))), nil)
	if err != nil {
		cfg.LogInfo(ctx, "the issuer's federation fetch endpoint is not a usable url", slog.String("issuer", string(issuer.Sub)), slog.String("error", model.TruncateForResponse(err.Error())))
		return nil, nil, model.NewInvalidTrustChainError("the issuer's federation fetch endpoint is not a usable url")
	}
	request.Header.Set("Accept", "application/entity-statement+jwt")

	response, err := cfg.HttpClient.Do(request)
	if err != nil {
		if ended := fetchEnded(ctx, fetchCtx, cfg, issuer); ended != nil {
			return nil, nil, ended
		}
		cfg.LogInfo(ctx, "failed to reach the issuer's federation fetch endpoint", slog.String("issuer", string(issuer.Sub)), slog.String("error", model.TruncateForResponse(err.Error())))
		if classified := model.ReclassifyWithDescription(err, "failed to reach the issuer's federation fetch endpoint"); classified != nil {
			return nil, nil, classified
		}
		return nil, nil, model.NewInvalidTrustChainError("failed to reach the issuer's federation fetch endpoint")
	}
	defer response.Body.Close() //nolint:errcheck

	if err := fetchEnded(ctx, fetchCtx, cfg, issuer); err != nil {
		return nil, nil, err
	}

	if response.StatusCode != http.StatusOK {
		cfg.LogInfo(ctx, "non-200 response from the issuer's federation fetch endpoint", slog.String("issuer", string(issuer.Sub)), slog.String("status", model.TruncateForResponse(response.Status)))
		return nil, nil, model.NewInvalidTrustChainError("non-200 response from the issuer's federation fetch endpoint")
	}

	if !strings.Contains(response.Header.Get("Content-Type"), "application/entity-statement+jwt") { //todo: check on this - not sure if it has to be an exact match or not...
		cfg.LogInfo(ctx, "invalid Content-Type response from the issuer's federation fetch response", slog.String("issuer", string(issuer.Sub)), slog.String("content_type", model.TruncateForResponse(response.Header.Get("Content-Type"))))
		return nil, nil, model.NewInvalidTrustChainError("invalid Content-Type response from the issuer's federation fetch response")
	}

	limit := cfg.PeerResponseLimit()
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		cfg.LogInfo(ctx, "failed to read the issuer's federation fetch response body", slog.String("issuer", string(issuer.Sub)), slog.String("error", model.TruncateForResponse(err.Error())))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("%w%s: %w", model.ErrTemporarilyUnavailable, "this server did not complete the request", ctxErr)
		}
		return nil, nil, model.NewInvalidTrustChainError("failed to read the issuer's federation fetch response body")
	}
	if err := fetchEnded(ctx, fetchCtx, cfg, issuer); err != nil {
		return nil, nil, err
	}
	if int64(len(responseBytes)) > limit {
		cfg.LogInfo(ctx, "the issuer's federation fetch response exceeded the response limit", slog.String("issuer", string(issuer.Sub)), slog.Int64("limit", limit))
		return nil, nil, model.NewInvalidTrustChainError(fmt.Sprintf("the issuer's federation fetch response exceeded the %d byte response limit", limit))
	}

	subordinateStatement, err := Validate(ctx, cfg, issuer, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	if subordinateStatement.Sub != subject {
		return nil, nil, model.NewInvalidTrustChainError("'sub' claim does not match the requested subject entity identifier")
	}

	model.LogPrivateKeyMembersInRawSet(ctx, &cfg, subordinateStatement.Iss, subordinateStatement.Sub, rawJWKSClaim(string(responseBytes)))

	return josemodel.Pointer(string(responseBytes)), subordinateStatement, nil
}

func Validate(ctx context.Context, cfg model.Configuration, issuer model.EntityStatement, subordinateStatementJwt string) (*model.EntityStatement, error) {
	subordinateStatement, err := validate(ctx, cfg, issuer, subordinateStatementJwt)
	if err != nil {
		if errors.Is(err, model.ErrInvalidMetadata) || errors.Is(err, model.ErrInvalidTrustChain) {
			return nil, err
		}
		return nil, model.NewInvalidTrustChainError(err.Error())
	}
	return subordinateStatement, nil
}

func validate(ctx context.Context, cfg model.Configuration, issuer model.EntityStatement, subordinateStatementJwt string) (*model.EntityStatement, error) {
	parts := strings.Split(subordinateStatementJwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT structure")
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %s", err.Error())
	}
	if err := model.VerifyJSONValueCount(head, cfg.StatementValuesLimit()); err != nil {
		return nil, fmt.Errorf("the JWT header %s", err.Error())
	}
	var headMap map[string]any
	err = json.Unmarshal(head, &headMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT header: %s", err.Error())
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT body: %s", err.Error())
	}
	if err := model.VerifyJSONValueCount(body, cfg.StatementValuesLimit()); err != nil {
		return nil, fmt.Errorf("the JWT body %s", err.Error())
	}
	var bodyMap map[string]any
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT body: %s", err.Error())
	}
	if err := model.VerifyTrustMarkValueCount(bodyMap, cfg.StatementValuesLimit()); err != nil {
		return nil, fmt.Errorf("the JWT body %s", err.Error())
	}

	if err = entity_statement.ValidateStatementHeader(headMap); err != nil {
		return nil, err
	}

	kid, ok := headMap["kid"]
	if !ok {
		return nil, fmt.Errorf("missing required header claim 'kid'")
	}
	sKid, ok := kid.(string)
	if !ok {
		return nil, fmt.Errorf("malformed header claim 'kid'")
	}

	if err = entity_statement.VerifyAgainstJwks(ctx, subordinateStatementJwt, sKid, issuer.JWKs); err != nil {
		return nil, err
	}
	for _, claim := range []string{"authority_hints", "trust_anchor_hints", "trust_marks", "trust_mark_issuers", "trust_mark_owners"} {
		if _, present := bodyMap[claim]; present {
			return nil, model.NewInvalidTrustChainError(fmt.Sprintf("the %q claim is permitted only in entity configurations, not in a subordinate statement", claim))
		}
	}

	var subordinateStatement model.EntityStatement
	err = json.Unmarshal(body, &subordinateStatement)
	if err != nil {
		if errors.Is(err, model.ErrInvalidMetadata) {
			return nil, fmt.Errorf("invalid entity statement: %w", err)
		}
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("invalid entity statement: %s", err.Error()))
	}

	if subordinateStatement.Iss == subordinateStatement.Sub {
		return nil, model.NewInvalidTrustChainError("a statement whose 'iss' and 'sub' claims match is an entity configuration, not a subordinate statement")
	}

	if subordinateStatement.Iss != issuer.Sub {
		return nil, fmt.Errorf("'iss' claim does not match issuer 'sub' claim")
	}

	if subordinateStatement.Metadata != nil {
		if err = subordinateStatement.Metadata.Verify(cfg.EntityTypes, cfg.DiscardUnrecognisedEntityTypes); err != nil {
			return nil, model.NewInvalidMetadataError(err.Error())
		}
	}

	if subordinateStatement.MetadataPolicy != nil {
		if err = subordinateStatement.MetadataPolicy.Verify(cfg.EntityTypes, cfg.DiscardUnrecognisedEntityTypes); err != nil {
			return nil, model.NewInvalidMetadataError(err.Error())
		}
	}

	return &subordinateStatement, nil
}

// todo: check this conforms to the errors listed in openid federation (spoiler alert - it doesn't)
// New takes a given subject Entity Identifier, set of authority hint Entity Identifiers, populated Entity Statement, and key material (with associated key ID and algorithm) and produces a signed Entity Configuration
const signingFailureError = "unable to produce the subordinate statement at this time"

func New(ctx context.Context, subjectIdentifier model.EntityIdentifier, subordinateRetriever func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error), configuration model.ServerConfiguration) (*string, error) {
	if configuration.IntermediateConfiguration == nil {
		return nil, fmt.Errorf("no intermediate configuration provided")
	}

	if model.NamesTheSameEntity(subjectIdentifier, configuration.EntityIdentifier) {
		return nil, model.NewInvalidSubjectError("an entity cannot issue a subordinate statement about itself, as a statement whose 'iss' and 'sub' claims match is an entity configuration")
	}

	subjectSubordinateConfiguration, signerConfiguration, err := subordinateRetriever()
	if err != nil {
		return nil, err
	}
	if subjectSubordinateConfiguration == nil {
		return nil, model.NewNotFoundError("unknown entity identifier")
	}

	if len(subjectSubordinateConfiguration.JWKs.Keys) == 0 {
		return nil, fmt.Errorf("no jwk values provided for subject subordinate entity identifier")
	}

	seen := map[string]struct{}{}
	publishable := josemodel.Jwks{Keys: make([]map[string]any, 0, len(subjectSubordinateConfiguration.JWKs.Keys))}
	for _, k := range subjectSubordinateConfiguration.JWKs.Keys {
		kid, ok := k["kid"]
		if !ok {
			return nil, fmt.Errorf("one or more of the provided subordinate configuration JWKs is missing the mandatory field 'kid'")
		}
		sKid, ok := kid.(string)
		if !ok {
			return nil, fmt.Errorf("one or more of the provided subordinate configuration JWKs has a malformed 'kid' value")
		}
		if _, duplicate := seen[sKid]; duplicate {
			return nil, fmt.Errorf("all provided subordinate configuration JWKs must have unique 'kid' values - %q appears more than once", sKid)
		}
		seen[sKid] = struct{}{}

		if err := model.VerifyPublishableJWK(k); err != nil {
			configuration.LogError(ctx, "dropping a registered key from a subordinate statement because it carries private key material", slog.String("subject", string(subjectIdentifier)), slog.String("kid", model.TruncateForResponse(sKid)), slog.String("error", err.Error()))
			continue
		}
		if declared, ok := k["alg"].(string); ok {
			if err := model.VerifyKeyStrength(k, declared); err != nil {
				configuration.LogError(ctx, "dropping a registered key from a subordinate statement because its modulus is outside the sizes this library verifies for the algorithm it is registered for", slog.String("subject", string(subjectIdentifier)), slog.String("kid", model.TruncateForResponse(sKid)), slog.String("error", err.Error()))
				continue
			}
		}
		publishable.Keys = append(publishable.Keys, k)
	}

	if len(publishable.Keys) == 0 {
		return nil, model.NewInvalidSubjectError("every key registered for this subject is unpublishable, so no usable subordinate statement can be issued for it")
	}

	subordinateStatementLifetime, err := model.ResolveStatementLifetime("SubordinateStatementLifetime", configuration.IntermediateConfiguration.SubordinateStatementLifetime, model.DefaultSubordinateStatementLifetime)
	if err != nil {
		return nil, err
	}

	subordinateStatement := model.EntityStatement{
		Sub:  subjectIdentifier,
		Iss:  configuration.EntityIdentifier,
		Iat:  time.Now().UTC().Unix(),
		Exp:  time.Now().Add(subordinateStatementLifetime).UTC().Unix(),
		JWKs: publishable,
	}

	if unrecognised := subjectSubordinateConfiguration.Policies.UnrecognisedOperators(); len(unrecognised) > 0 {
		return nil, fmt.Errorf("the metadata policy configured for %s holds operators this library does not understand, so it cannot publish them: %s", model.TruncateForResponse(string(subjectIdentifier)), model.TruncateForResponse(strings.Join(unrecognised, ", ")))
	}
	if policy := subjectSubordinateConfiguration.Policies; policy.HasParameterPolicies() {
		subordinateStatement.MetadataPolicy = &policy
	}

	if signerConfiguration.KeyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	subordinateStatementBytes, err := json.Marshal(subordinateStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize entity configuration: %s", err.Error())
	}

	var subordinateStatementMap map[string]any
	err = json.Unmarshal(subordinateStatementBytes, &subordinateStatementMap)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize entity configuration: %s", err.Error())
	}

	if err = model.VerifyPublishableStatementKeys(subordinateStatementMap); err != nil {
		return nil, fmt.Errorf("refusing to publish this subordinate statement because %s", err.Error())
	}

	if err = model.VerifyIssuedStatement(subordinateStatementBytes, configuration.EntityTypes); err != nil {
		return nil, fmt.Errorf("refusing to publish a subordinate statement this implementation would reject: %s", err.Error())
	}

	if jwa.GetAlgorithm(signerConfiguration.Algorithm) == jwa.Unknown {
		return nil, fmt.Errorf("refusing to publish a subordinate statement this implementation would reject: %q is not a supported signing algorithm", signerConfiguration.Algorithm)
	}

	token, err := jwt.New(signerConfiguration.Signer, map[string]any{
		"kid": signerConfiguration.KeyID,
		"typ": "entity-statement+jwt",
		"alg": signerConfiguration.Algorithm,
	}, subordinateStatementMap, jwt.Opts{Algorithm: jwa.GetAlgorithm(signerConfiguration.Algorithm)})
	if err != nil {
		if errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || errors.Is(err, joseerror.ErrInvalidPrivateKey) {
			return nil, fmt.Errorf("refusing to publish a subordinate statement this implementation would reject: %s", err.Error())
		}
		configuration.LogError(ctx, "the signer could not sign the subordinate statement", slog.String("error", model.TruncateForResponse(err.Error())))
		return nil, model.ClassifySignerError(err, signingFailureError)
	}

	if err = entity_statement.VerifyIssuedSignature(ctx, *token, signerConfiguration.KeyID, signerConfiguration.Algorithm, signerConfiguration.Signer); err != nil {
		return nil, fmt.Errorf("refusing to publish a subordinate statement this implementation would reject: %s", err.Error())
	}

	return token, nil
}

func rawJWKSClaim(statement string) any {
	parts := strings.Split(statement, ".")
	if len(parts) != 3 {
		return nil
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var bodyMap map[string]any
	if json.Unmarshal(body, &bodyMap) != nil {
		return nil
	}
	return bodyMap["jwks"]
}

func fetchEnded(ctx, fetchCtx context.Context, cfg model.Configuration, issuer model.EntityStatement) error {
	if fetchCtx.Err() == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		cfg.LogInfo(ctx, "stopped fetching from the issuer's federation fetch endpoint because this request ended", slog.String("issuer", string(issuer.Sub)))
		return fmt.Errorf("%w%s: %w", model.ErrTemporarilyUnavailable, "this server did not complete the request", ctxErr)
	}
	cfg.LogInfo(ctx, "the issuer's federation fetch response did not arrive within the peer deadline", slog.String("issuer", string(issuer.Sub)))
	return model.NewInvalidTrustChainError("the issuer's federation fetch response did not arrive within the peer deadline")
}
