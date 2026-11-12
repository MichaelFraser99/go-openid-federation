package trust_marks

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_chain"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Status(ctx context.Context, cfg model.ServerConfiguration, trustMark string) (*model.TrustMarkStatusResponse, error) {
	if cfg.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	if !issuedBy(trustMark, cfg.EntityIdentifier, cfg.StatementValuesLimit()) {
		cfg.LogInfo(ctx, "trust mark status requested for a value that is not a trust mark this server issued, treating it as unknown")
		return nil, model.NewNotFoundError("unknown trust mark")
	}

	status, err := cfg.TrustMarkRetriever.GetTrustMarkStatus(ctx, trustMark)
	if err != nil {
		return nil, err
	}
	if status == nil || strings.TrimSpace(*status) == "" {
		cfg.LogInfo(ctx, "trust mark status retriever returned no status and no error, treating the trust mark as unknown")
		return nil, model.NewNotFoundError("unknown trust mark")
	}
	cfg.LogInfo(ctx, "trust mark status determined", slog.String("status", *status))

	return &model.TrustMarkStatusResponse{Status: *status}, nil
}

func issuedBy(trustMark string, issuer model.EntityIdentifier, valueLimit int) bool {
	parts := strings.SplitN(trustMark, ".", 4)
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	if model.VerifyJSONValueCount(payload, valueLimit) != nil {
		return false
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	iss, _ := claims["iss"].(string)
	return iss == string(issuer)
}

func List(ctx context.Context, cfg model.ServerConfiguration, trustMarkIdentifier string, subjectEntityIdentifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	if cfg.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	trustMarkedEntities, err := cfg.TrustMarkRetriever.ListTrustMarks(ctx, trustMarkIdentifier, subjectEntityIdentifier)
	if err != nil {
		return nil, err
	}

	return trustMarkedEntities, nil
}

func Issue(ctx context.Context, cfg model.ServerConfiguration, trustMarkIdentifier string, subjectEntityIdentifier model.EntityIdentifier) (*string, error) {
	if cfg.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	trustMark, err := cfg.TrustMarkRetriever.IssueTrustMark(ctx, trustMarkIdentifier, subjectEntityIdentifier)
	if err != nil {
		return nil, err
	}
	if trustMark == nil || strings.TrimSpace(*trustMark) == "" {
		cfg.LogInfo(ctx, "trust mark issuer returned no trust mark and no error, treating the entity as not holding it")
		return nil, model.NewNotFoundError("entity does not have the specified trust mark")
	}
	if err := verifyIssued(*trustMark, cfg.EntityIdentifier, trustMarkIdentifier, subjectEntityIdentifier); err != nil {
		return nil, model.NewServerError("the trust mark retriever returned a value that is not the requested trust mark: " + err.Error())
	}

	return trustMark, nil
}

func verifyIssued(trustMark string, issuer model.EntityIdentifier, trustMarkType string, subject model.EntityIdentifier) error {
	parts := strings.SplitN(trustMark, ".", 4)
	if len(parts) != 3 {
		return errors.New("it is not a compact JWS")
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("its header is not base64url")
	}
	var head map[string]any
	if json.Unmarshal(headBytes, &head) != nil {
		return errors.New("its header is not a JSON object")
	}
	if typ, _ := head["typ"].(string); !entity_statement.NamesJWTType(typ, "trust-mark+jwt") {
		return errors.New("its 'typ' header is not trust-mark+jwt")
	}
	if alg, _ := head["alg"].(string); alg == "" || alg == "none" {
		return errors.New("it is not signed")
	}
	if kid, _ := head["kid"].(string); kid == "" {
		return errors.New("its 'kid' header is not a non-empty string")
	}
	if signature, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(signature) == 0 {
		return errors.New("it carries no signature")
	}
	bodyBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("its payload is not base64url")
	}
	var body model.TrustMark
	if json.Unmarshal(bodyBytes, &body) != nil {
		return errors.New("its payload is not a trust mark")
	}
	if body.Issuer != string(issuer) {
		return errors.New("its 'iss' is not this server")
	}
	if body.Sub != string(subject) {
		return errors.New("its 'sub' is not the requested subject")
	}
	if body.Type != trustMarkType {
		return errors.New("its 'trust_mark_type' is not the requested type")
	}
	return nil
}

type ValidateOptions struct {
	ExpectedType             string
	ExpectedSubject          model.EntityIdentifier
	AuthorizedIssuers        []model.EntityIdentifier
	TrustAnchor              model.EntityIdentifier
	TrustAnchorConfiguration model.EntityStatement

	issuerKeys *issuerKeyCache
}

type issuerKeyResult struct {
	keys *josemodel.Jwks
	err  error
}

type issuerKeyCache struct {
	results map[model.EntityIdentifier]issuerKeyResult
	limit   int
}

func newIssuerKeyCache(limit int) *issuerKeyCache {
	return &issuerKeyCache{results: map[model.EntityIdentifier]issuerKeyResult{}, limit: limit}
}

const ownEntityConfigurationUnavailable = "unable to produce the entity configuration at this time"

const ownSubordinateStatementUnavailable = "unable to produce the subordinate statement at this time"

var errTooManyTrustMarkIssuers = fmt.Errorf("too many distinct trust mark issuers")

func (c *issuerKeyCache) lookup(issuer model.EntityIdentifier, resolve func() (*josemodel.Jwks, error)) (*josemodel.Jwks, error) {
	if c == nil {
		return resolve()
	}
	if result, known := c.results[issuer]; known {
		return result.keys, result.err
	}
	if len(c.results) >= c.limit {
		return nil, errTooManyTrustMarkIssuers
	}
	keys, err := resolve()
	c.results[issuer] = issuerKeyResult{keys: keys, err: err}
	return keys, err
}

func FilterByTrusted(ctx context.Context, cfg model.Configuration, resolved *model.ResolveResponse, trustAnchorConfiguration model.EntityStatement, cache *resolvecache.Cache) error {
	cfg.LogInfo(ctx, "filtering trust marks by those trusted by the trust anchor")

	limit := cfg.TrustMarkIssuerLimit()
	issuerKeys := newIssuerKeyCache(limit)
	presented := len(resolved.TrustMarks)
	markLimit := cfg.TrustMarkLimit()
	verified, untrusted, unverified := 0, 0, 0
	trustedTrustMarks := make([]model.TrustMarkHolder, 0, min(presented, markLimit))
	for _, tm := range resolved.TrustMarks {
		authorizedIssuers, trusted := trustAnchorConfiguration.TrustMarkIssuers[tm.TrustMarkType]
		if !trusted {
			untrusted++
			continue
		}
		if verified == markLimit {
			unverified++
			continue
		}
		verified++

		validated, err := Validate(ctx, cfg, tm.TrustMark, ValidateOptions{
			ExpectedType:             tm.TrustMarkType,
			ExpectedSubject:          resolved.Sub,
			AuthorizedIssuers:        authorizedIssuers,
			TrustAnchor:              trustAnchorConfiguration.Sub,
			TrustAnchorConfiguration: trustAnchorConfiguration,
			issuerKeys:               issuerKeys,
		}, cache)
		if errors.Is(err, errTooManyTrustMarkIssuers) {
			cfg.LogInfo(ctx, "subject presents trust marks from more distinct issuers than the configured limit", slog.Int("limit", limit), slog.String("subject", string(resolved.Sub)))
			resolved.TrustMarks = nil
			return fmt.Errorf("%w%w%s", model.ErrInvalidSubject, model.ErrLimitReached, fmt.Sprintf("the subject presents trust marks from more than %d distinct issuers, which is more than this resolver will verify", limit))
		}
		if errors.Is(err, resolvecache.ErrOwnFault) {
			statement, description := "entity configuration", ownEntityConfigurationUnavailable
			if errors.Is(err, resolvecache.ErrOwnIssuedFault) {
				statement, description = "subordinate statement", ownSubordinateStatementUnavailable
			}
			classified := model.ClassifySignerError(err, description)
			if !errors.Is(err, resolvecache.ErrLogged) {
				msg := "this resolver could not produce its own " + statement + " for a trust mark issuer walk"
				if errors.Is(classified, model.ErrTemporarilyUnavailable) {
					cfg.LogInfo(ctx, msg, slog.String("trust_mark_type", model.TruncateForResponse(tm.TrustMarkType)), slog.String("error", model.TruncateForResponse(err.Error())))
				} else {
					cfg.LogError(ctx, msg, slog.String("trust_mark_type", model.TruncateForResponse(tm.TrustMarkType)), slog.String("error", model.TruncateForResponse(err.Error())))
				}
			}
			resolved.TrustMarks = nil
			return fmt.Errorf("%w%w", resolvecache.ErrLogged, classified)
		}
		if err != nil {
			cfg.LogInfo(ctx, "failed to validate trust mark", slog.String("trust_mark_type", model.TruncateForResponse(tm.TrustMarkType)), slog.String("error", model.TruncateForResponse(err.Error())))
			continue
		}

		if validated.Expiry != nil && *validated.Expiry <= time.Now().UTC().Unix() {
			cfg.LogInfo(ctx, "omitting a trust mark whose expiry has passed, because the response expiry is the minimum over the marks it carries", slog.String("trust_mark_type", model.TruncateForResponse(tm.TrustMarkType)), slog.Int64("exp", *validated.Expiry))
			continue
		}

		trustedTrustMarks = append(trustedTrustMarks, tm)
		if validated.Expiry != nil && *validated.Expiry < resolved.Exp {
			resolved.Exp = *validated.Expiry
		}
	}
	if unverified > 0 {
		cfg.LogInfo(ctx, "the subject presents more trust marks of types the trust anchor trusts than this resolver will verify, dropping those past the limit unverified", slog.Int("limit", markLimit), slog.Int("unverified", unverified))
	}
	if presented > 0 {
		cfg.LogInfo(ctx, "dropped trust marks the trust anchor does not trust or this resolver could not verify", slog.Int("dropped", presented-len(trustedTrustMarks)), slog.Int("presented", presented), slog.Int("untrusted_types", untrusted))
	}
	resolved.TrustMarks = trustedTrustMarks
	return nil
}

func issuerFederationKeys(ctx context.Context, cfg model.Configuration, issuer model.EntityIdentifier, opts ValidateOptions, cache *resolvecache.Cache) (*josemodel.Jwks, error) {
	return opts.issuerKeys.lookup(issuer, func() (*josemodel.Jwks, error) {
		if issuer == opts.TrustAnchor {
			jwks := opts.TrustAnchorConfiguration.JWKs
			return &jwks, nil
		}

		_, parsedChain, _, err := trust_chain.BuildTrustChain(ctx, cfg, issuer, opts.TrustAnchor, cache)
		if err != nil {
			return nil, fmt.Errorf("unable to establish trust in trust mark issuer %s through trust anchor %s: %w", issuer, opts.TrustAnchor, err)
		}
		jwks := parsedChain[0].JWKs
		return &jwks, nil
	})
}

func Validate(ctx context.Context, cfg model.Configuration, trustMark string, opts ValidateOptions, cache *resolvecache.Cache) (*model.TrustMark, error) {
	cfg.LogInfo(ctx, "validating trust mark", slog.String("trust_mark", model.TruncateForResponse(trustMark)))

	if opts.ExpectedType == "" {
		return nil, fmt.Errorf("an expected trust mark type must be supplied to validate a trust mark")
	}
	if opts.ExpectedSubject == "" {
		return nil, fmt.Errorf("an expected trust mark subject must be supplied to validate a trust mark")
	}

	parts := strings.Split(trustMark, ".")
	if len(parts) != 3 {
		cfg.LogInfo(ctx, "invalid JWT structure", slog.String("trust_mark", model.TruncateForResponse(trustMark)), slog.Int("parts_count", len(parts)))
		return nil, fmt.Errorf("invalid JWT structure")
	}

	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		cfg.LogInfo(ctx, "failed to decode JWT header", slog.String("error", err.Error()), slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("failed to decode JWT header: %v", err)
	}
	if err := model.VerifyJSONValueCount(headBytes, cfg.StatementValuesLimit()); err != nil {
		cfg.LogInfo(ctx, "trust mark header exceeds the value limit", slog.Int("limit", cfg.StatementValuesLimit()))
		return nil, fmt.Errorf("the trust mark's JWT header %s", err.Error())
	}
	var headMap map[string]any
	if err = json.Unmarshal(headBytes, &headMap); err != nil {
		cfg.LogInfo(ctx, "failed to unmarshal JWT header", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to unmarshal JWT header: %v", err)
	}

	kid, ok := headMap["kid"].(string)
	if !ok || kid == "" {
		cfg.LogInfo(ctx, "trust mark is missing a usable 'kid' header", slog.Any("kid", headMap["kid"]))
		return nil, fmt.Errorf("trust mark header claim 'kid' must be a non-empty string")
	}
	if err := entity_statement.VerifyNoCriticalHeader(headMap); err != nil {
		cfg.LogInfo(ctx, "trust mark header carries a critical extension", slog.String("error", err.Error()))
		return nil, fmt.Errorf("the trust mark's JWT header is refused: %s", err.Error())
	}
	if typ, _ := headMap["typ"].(string); !entity_statement.NamesJWTType(typ, "trust-mark+jwt") { //todo: support additional, approved, types
		cfg.LogInfo(ctx, "invalid trust mark type", slog.String("type", typ))
		return nil, fmt.Errorf("invalid trust mark type")
	}
	if alg, _ := headMap["alg"].(string); !slices.Contains(cfg.AcceptedSigningAlgorithms(), jwa.GetAlgorithm(alg)) {
		cfg.LogInfo(ctx, "trust mark header names an algorithm this deployment does not accept")
		return nil, fmt.Errorf("the trust mark's 'alg' header names an algorithm this deployment does not accept")
	}

	bodyBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		cfg.LogInfo(ctx, "failed to decode JWT body", slog.String("error", err.Error()), slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("failed to decode JWT body: %v", err)
	}
	if err := model.VerifyJSONValueCount(bodyBytes, cfg.StatementValuesLimit()); err != nil {
		cfg.LogInfo(ctx, "trust mark body exceeds the value limit", slog.Int("limit", cfg.StatementValuesLimit()))
		return nil, fmt.Errorf("the trust mark's JWT body %s", err.Error())
	}
	var body model.TrustMark
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		cfg.LogInfo(ctx, "failed to unmarshal JWT body", slog.String("error", err.Error()), slog.String("body", model.TruncateForResponse(string(bodyBytes))))
		return nil, fmt.Errorf("failed to unmarshal JWT body: %v", err)
	}

	if body.Issuer == "" {
		cfg.LogInfo(ctx, "trust mark issuer is missing", slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("trust mark issuer is missing")
	}

	parsedIssuer, err := model.ValidateEntityIdentifier(body.Issuer)
	if err != nil {
		cfg.LogInfo(ctx, "invalid trust mark issuer", slog.String("error", err.Error()), slog.String("issuer", body.Issuer))
		return nil, fmt.Errorf("invalid trust mark issuer: %v", err)
	}

	if body.Type != opts.ExpectedType {
		cfg.LogInfo(ctx, "trust mark type does not match the type it is presented under", slog.String("signed_type", body.Type), slog.String("presented_type", opts.ExpectedType))
		return nil, fmt.Errorf("trust mark type %q does not match the signed trust_mark_type %q", opts.ExpectedType, body.Type)
	}

	if body.Sub != string(opts.ExpectedSubject) {
		cfg.LogInfo(ctx, "trust mark subject does not match the resolved subject", slog.String("trust_mark_sub", body.Sub), slog.String("expected_sub", string(opts.ExpectedSubject)))
		return nil, fmt.Errorf("trust mark subject %q does not match the entity presenting it %q", body.Sub, opts.ExpectedSubject)
	}

	if len(opts.AuthorizedIssuers) > 0 && !slices.Contains(opts.AuthorizedIssuers, *parsedIssuer) {
		cfg.LogInfo(ctx, "trust mark issuer not authorized", slog.String("issuer", string(*parsedIssuer)), slog.Any("authorized_issuers", opts.AuthorizedIssuers))
		return nil, fmt.Errorf("trust mark issuer is not authorized within the current federation")
	}

	issuerKeys, err := issuerFederationKeys(ctx, cfg, *parsedIssuer, opts, cache)
	if errors.Is(err, model.ErrServerError) && !errors.Is(err, resolvecache.ErrOwnFault) {
		cfg.LogError(ctx, "this resolver's own configuration prevents establishing trust in the trust mark issuer", slog.String("error", err.Error()), slog.String("issuer", string(*parsedIssuer)))
		return nil, err
	}
	if err != nil {
		cfg.LogInfo(ctx, "failed to establish trust in trust mark issuer", slog.String("error", err.Error()), slog.String("issuer", string(*parsedIssuer)))
		return nil, err
	}

	selectedKey, err := entity_statement.SelectKey(*issuerKeys, kid)
	if err != nil {
		cfg.LogInfo(ctx, "trust mark kid does not match a key published for the issuer", slog.String("kid", kid), slog.String("issuer", string(*parsedIssuer)), slog.String("error", err.Error()))
		return nil, fmt.Errorf("trust mark 'kid' %q does not match a federation entity key published by issuer %s: %s", model.TruncateForResponse(kid), *parsedIssuer, err.Error())
	}

	if err = entity_statement.VerifySelectedKey(trustMark, selectedKey, cfg.AcceptedSigningAlgorithms()); err != nil {
		cfg.LogInfo(ctx, "the key published for the trust mark issuer cannot verify this trust mark", slog.String("kid", kid), slog.String("issuer", string(*parsedIssuer)), slog.String("error", err.Error()))
		return nil, fmt.Errorf("the trust mark 'kid' %q names a key published by issuer %s that cannot verify it: %s", model.TruncateForResponse(kid), *parsedIssuer, model.TruncateForResponse(err.Error()))
	}

	_, _, err = jwt.Validate(ctx, trustMark, func() ([]crypto.PublicKey, error) {
		pubKey, err := jwk.PublicFromJwk(selectedKey)
		if err != nil {
			cfg.LogInfo(ctx, "the key published for the trust mark issuer cannot be read", slog.String("kid", kid), slog.String("issuer", string(*parsedIssuer)), slog.Any("members", slices.Sorted(maps.Keys(selectedKey))), slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to parse JWK as a valid public key: %w", err)
		}
		return []crypto.PublicKey{pubKey}, nil
	}, &josemodel.JoseOptions{
		UseTokenProvidedKeys:     false,
		ClockSkewLeeway:          model.ClockSkewLeeway,
		AllowedSigningAlgorithms: cfg.AcceptedSigningAlgorithms(),
	})
	if err != nil {
		cfg.LogInfo(ctx, "failed to validate trust mark", slog.String("error", err.Error()), slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("failed to validate trust mark: %v", err)
	}

	if err := verifyDelegationRequirement(ctx, cfg, body, *parsedIssuer, opts.TrustAnchorConfiguration.TrustMarkOwners); err != nil {
		return nil, err
	}

	return &body, nil
}
