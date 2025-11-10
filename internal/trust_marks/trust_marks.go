package trust_marks

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
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

	return trustMark, nil
}

func FilterByTrusted(ctx context.Context, cfg model.Configuration, resolved *model.ResolveResponse, trustAnchorConfiguration model.EntityStatement) error {
	cfg.LogInfo(ctx, "filtering trust marks by those trusted by the trust anchor")

	var trustedTrustMarks []model.TrustMarkHolder
	for _, tm := range resolved.TrustMarks {
		for trustedTmType, trustedTmIssuers := range trustAnchorConfiguration.TrustMarkIssuers {
			if tm.TrustMarkType == trustedTmType {
				_, err := Validate(ctx, cfg, tm.TrustMark, trustedTmIssuers)
				if err != nil {
					cfg.LogInfo(ctx, "failed to validate trust mark", slog.String("trust_mark_type", tm.TrustMarkType), slog.String("trust_mark", tm.TrustMark), slog.String("error", err.Error()))
					continue
				}
				trustedTrustMarks = append(trustedTrustMarks, tm)
				break
			}
		}

		if !slices.Contains(trustedTrustMarks, tm) {
			cfg.LogInfo(ctx, "trust mark type is not trusted by the trust anchor, omitting", slog.String("trust_mark_type", tm.TrustMarkType))
		}
	}
	resolved.TrustMarks = trustedTrustMarks
	return nil
}

// todo: this will need updating to support delegation
func Validate(ctx context.Context, cfg model.Configuration, trustMark string, authorizedIssuers []model.EntityIdentifier) (*model.TrustMark, error) {
	cfg.LogInfo(ctx, "validating trust mark", slog.String("trust_mark", trustMark))

	parts := strings.Split(trustMark, ".")
	if len(parts) != 3 {
		cfg.LogError(ctx, "invalid JWT structure", slog.String("trust_mark", trustMark), slog.Int("parts_count", len(parts)))
		return nil, fmt.Errorf("invalid JWT structure")
	}

	bodyBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		cfg.LogError(ctx, "failed to decode JWT body", slog.String("error", err.Error()), slog.String("trust_mark", trustMark))
		return nil, fmt.Errorf("failed to decode JWT body: %v", err)
	}
	var body model.TrustMark
	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		cfg.LogError(ctx, "failed to unmarshal JWT body", slog.String("error", err.Error()), slog.String("body", string(bodyBytes)))
		return nil, fmt.Errorf("failed to unmarshal JWT body: %v", err)
	}

	if body.Issuer == "" {
		cfg.LogError(ctx, "trust mark issuer is missing", slog.String("trust_mark", trustMark))
		return nil, fmt.Errorf("trust mark issuer is missing")
	}

	parsedIssuer, err := model.ValidateEntityIdentifier(body.Issuer)
	if err != nil {
		cfg.LogError(ctx, "invalid trust mark issuer", slog.String("error", err.Error()), slog.String("issuer", body.Issuer))
		return nil, fmt.Errorf("invalid trust mark issuer: %v", err)
	}

	if !slices.Contains(authorizedIssuers, *parsedIssuer) {
		cfg.LogError(ctx, "trust mark issuer not authorized", slog.String("issuer", string(*parsedIssuer)), slog.Any("authorized_issuers", authorizedIssuers))
		return nil, fmt.Errorf("trust mark issuer is not authorized within the current federation")
	}

	_, issuerConfiguration, err := entity_configuration.Retrieve(ctx, cfg, *parsedIssuer)
	if err != nil {
		cfg.LogError(ctx, "failed to retrieve issuer entity configuration", slog.String("error", err.Error()), slog.String("issuer", string(*parsedIssuer)))
		return nil, fmt.Errorf("failed to retrieve issuer entity configuration: %v", err)
	}

	head, _, err := jwt.Validate(trustMark, func() ([]crypto.PublicKey, error) {
		var publicKeys []crypto.PublicKey
		for _, key := range issuerConfiguration.JWKs.Keys {
			pubKey, err := jwk.PublicFromJwk(key)
			if err != nil {
				cfg.LogError(ctx, "failed to parse JWK", slog.String("error", err.Error()), slog.Any("jwk", key))
				return nil, fmt.Errorf("failed to parse JWK as a valid public key: %w", err)
			}
			publicKeys = append(publicKeys, pubKey)
		}
		return publicKeys, nil
	}, &josemodel.JoseOptions{
		UseTokenProvidedKeys: false,
	})

	if typ, ok := head["typ"].(string); !ok {
		return nil, fmt.Errorf("missing or invalid required field 'typ'")
	} else if typ != "trust-mark+jwt" { //todo: support additional, approved, types
		cfg.LogError(ctx, "invalid trust mark type", slog.String("type", typ))
		return nil, fmt.Errorf("invalid trust mark type")
	}
	return &body, nil
}
