package trust_marks

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

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

	status, err := cfg.TrustMarkRetriever.GetTrustMarkStatus(ctx, trustMark)
	if err != nil {
		cfg.LogInfo(ctx, "error determining trust mark status", slog.String("error", err.Error()))
		return nil, err
	}
	if status == nil || strings.TrimSpace(*status) == "" {
		cfg.LogInfo(ctx, "trust mark status retriever returned no status and no error, treating the trust mark as unknown")
		return nil, model.NewNotFoundError("unknown trust mark")
	}
	cfg.LogInfo(ctx, "trust mark status determined", slog.String("status", *status))

	return &model.TrustMarkStatusResponse{Status: *status}, nil
}

func List(ctx context.Context, cfg model.ServerConfiguration, trustMarkIdentifier string, subjectEntityIdentifier *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	if cfg.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	trustMarkedEntities, err := cfg.TrustMarkRetriever.ListTrustMarks(ctx, trustMarkIdentifier, subjectEntityIdentifier)
	if err != nil {
		cfg.LogInfo(ctx, "error listing trust marks", slog.String("error", err.Error()))
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
		cfg.LogInfo(ctx, "error issuing trust mark", slog.String("error", err.Error()))
		return nil, err
	}
	if trustMark == nil || strings.TrimSpace(*trustMark) == "" {
		cfg.LogInfo(ctx, "trust mark issuer returned no trust mark and no error, treating the entity as not holding it")
		return nil, model.NewNotFoundError("entity does not have the specified trust mark")
	}

	return trustMark, nil
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
	trustedTrustMarks := make([]model.TrustMarkHolder, 0, len(resolved.TrustMarks))
	for _, tm := range resolved.TrustMarks {
		authorizedIssuers, trusted := trustAnchorConfiguration.TrustMarkIssuers[tm.TrustMarkType]
		if !trusted {
			cfg.LogInfo(ctx, "trust mark type is not trusted by the trust anchor, omitting", slog.String("trust_mark_type", tm.TrustMarkType))
			continue
		}

		validated, err := Validate(ctx, cfg, tm.TrustMark, ValidateOptions{
			ExpectedType:             tm.TrustMarkType,
			ExpectedSubject:          resolved.Sub,
			AuthorizedIssuers:        authorizedIssuers,
			TrustAnchor:              trustAnchorConfiguration.Sub,
			TrustAnchorConfiguration: trustAnchorConfiguration,
			issuerKeys:               issuerKeys,
		}, cache)
		if errors.Is(err, errTooManyTrustMarkIssuers) {
			cfg.LogError(ctx, "subject presents trust marks from more distinct issuers than the configured limit", slog.Int("limit", limit), slog.String("subject", string(resolved.Sub)))
			resolved.TrustMarks = nil
			return fmt.Errorf("%w%w%s", model.ErrInvalidSubject, model.ErrLimitReached, fmt.Sprintf("the subject presents trust marks from more than %d distinct issuers, which is more than this resolver will verify", limit))
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
		cfg.LogError(ctx, "invalid JWT structure", slog.String("trust_mark", model.TruncateForResponse(trustMark)), slog.Int("parts_count", len(parts)))
		return nil, fmt.Errorf("invalid JWT structure")
	}

	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		cfg.LogError(ctx, "failed to decode JWT header", slog.String("error", err.Error()), slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("failed to decode JWT header: %v", err)
	}
	var headMap map[string]any
	if err = json.Unmarshal(headBytes, &headMap); err != nil {
		cfg.LogError(ctx, "failed to unmarshal JWT header", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to unmarshal JWT header: %v", err)
	}

	kid, ok := headMap["kid"].(string)
	if !ok || kid == "" {
		cfg.LogError(ctx, "trust mark is missing a usable 'kid' header", slog.Any("kid", headMap["kid"]))
		return nil, fmt.Errorf("trust mark header claim 'kid' must be a non-empty string")
	}

	bodyBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		cfg.LogError(ctx, "failed to decode JWT body", slog.String("error", err.Error()), slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("failed to decode JWT body: %v", err)
	}
	var body model.TrustMark
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		cfg.LogError(ctx, "failed to unmarshal JWT body", slog.String("error", err.Error()), slog.String("body", string(bodyBytes)))
		return nil, fmt.Errorf("failed to unmarshal JWT body: %v", err)
	}

	if body.Issuer == "" {
		cfg.LogError(ctx, "trust mark issuer is missing", slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("trust mark issuer is missing")
	}

	parsedIssuer, err := model.ValidateEntityIdentifier(body.Issuer)
	if err != nil {
		cfg.LogError(ctx, "invalid trust mark issuer", slog.String("error", err.Error()), slog.String("issuer", body.Issuer))
		return nil, fmt.Errorf("invalid trust mark issuer: %v", err)
	}

	if body.Type != opts.ExpectedType {
		cfg.LogError(ctx, "trust mark type does not match the type it is presented under", slog.String("signed_type", body.Type), slog.String("presented_type", opts.ExpectedType))
		return nil, fmt.Errorf("trust mark type %q does not match the signed trust_mark_type %q", opts.ExpectedType, body.Type)
	}

	if body.Sub != string(opts.ExpectedSubject) {
		cfg.LogError(ctx, "trust mark subject does not match the resolved subject", slog.String("trust_mark_sub", body.Sub), slog.String("expected_sub", string(opts.ExpectedSubject)))
		return nil, fmt.Errorf("trust mark subject %q does not match the entity presenting it %q", body.Sub, opts.ExpectedSubject)
	}

	if len(opts.AuthorizedIssuers) > 0 && !slices.Contains(opts.AuthorizedIssuers, *parsedIssuer) {
		cfg.LogError(ctx, "trust mark issuer not authorized", slog.String("issuer", string(*parsedIssuer)), slog.Any("authorized_issuers", opts.AuthorizedIssuers))
		return nil, fmt.Errorf("trust mark issuer is not authorized within the current federation")
	}

	issuerKeys, err := issuerFederationKeys(ctx, cfg, *parsedIssuer, opts, cache)
	if err != nil {
		cfg.LogError(ctx, "failed to establish trust in trust mark issuer", slog.String("error", err.Error()), slog.String("issuer", string(*parsedIssuer)))
		return nil, err
	}

	selectedKey, err := entity_statement.SelectKey(*issuerKeys, kid)
	if err != nil {
		cfg.LogError(ctx, "trust mark kid does not match a key published for the issuer", slog.String("kid", kid), slog.String("issuer", string(*parsedIssuer)), slog.String("error", err.Error()))
		return nil, fmt.Errorf("trust mark 'kid' %q does not match a federation entity key published by issuer %s: %s", model.TruncateForResponse(kid), *parsedIssuer, err.Error())
	}

	if err = entity_statement.VerifySelectedKey(trustMark, selectedKey); err != nil {
		cfg.LogError(ctx, "the key published for the trust mark issuer cannot verify this trust mark", slog.String("kid", kid), slog.String("issuer", string(*parsedIssuer)), slog.String("error", err.Error()))
		return nil, fmt.Errorf("the trust mark 'kid' %q names a key published by issuer %s that cannot verify it: %s", model.TruncateForResponse(kid), *parsedIssuer, model.TruncateForResponse(err.Error()))
	}

	head, _, err := jwt.Validate(trustMark, func() ([]crypto.PublicKey, error) {
		pubKey, err := jwk.PublicFromJwk(selectedKey)
		if err != nil {
			cfg.LogError(ctx, "failed to parse JWK", slog.String("error", err.Error()), slog.Any("jwk", selectedKey))
			return nil, fmt.Errorf("failed to parse JWK as a valid public key: %w", err)
		}
		return []crypto.PublicKey{pubKey}, nil
	}, &josemodel.JoseOptions{
		UseTokenProvidedKeys: false,
		ClockSkewLeeway:      model.ClockSkewLeeway,
	})
	if err != nil {
		cfg.LogError(ctx, "failed to validate trust mark", slog.String("error", err.Error()), slog.String("trust_mark", model.TruncateForResponse(trustMark)))
		return nil, fmt.Errorf("failed to validate trust mark: %v", err)
	}

	if typ, ok := head["typ"].(string); !ok {
		return nil, fmt.Errorf("missing or invalid required field 'typ'")
	} else if typ != "trust-mark+jwt" { //todo: support additional, approved, types
		cfg.LogError(ctx, "invalid trust mark type", slog.String("type", typ))
		return nil, fmt.Errorf("invalid trust mark type")
	}

	if err := verifyDelegationRequirement(ctx, cfg, body, *parsedIssuer, opts.TrustAnchorConfiguration.TrustMarkOwners); err != nil {
		return nil, err
	}

	return &body, nil
}
