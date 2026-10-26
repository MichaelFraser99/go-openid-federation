package trust_marks

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const delegationJWTType = "trust-mark-delegation+jwt"

const maxDelegationNumericDate = float64(1 << 62)

func namesDelegationType(typ string) bool {
	return strings.EqualFold(typ, delegationJWTType) || strings.EqualFold(typ, "application/"+delegationJWTType)
}

func selectOwnerKeys(ctx context.Context, cfg model.Configuration, owner model.TrustMarkOwner, kid string) []map[string]any {
	selected := make([]map[string]any, 0, len(owner.JWKs.Keys))
	for _, key := range owner.JWKs.Keys {
		keyID, ok := key["kid"].(string)
		if !ok || keyID != kid {
			continue
		}
		if model.ValidateJWKShape(key) != nil {
			continue
		}
		if members := model.PrivateJWKMembers(key); len(members) > 0 {
			cfg.LogError(ctx, "the trust anchor publishes a trust mark owner key carrying private key material, so anyone holding that statement can mint delegations for this type, skipping it", slog.String("owner", string(owner.Sub)), slog.String("kid", model.TruncateForResponse(kid)), slog.Any("private_members", members))
			continue
		}
		selected = append(selected, key)
	}
	return selected
}

func describeHeaderMember(value any) string {
	if text, ok := value.(string); ok {
		return model.TruncateForResponse(text)
	}
	return model.TruncateForResponse(fmt.Sprintf("%v", value))
}

func delegationClaim(body map[string]any, claim string) (string, error) {
	value, present := body[claim]
	if !present {
		return "", fmt.Errorf("the delegation is missing the required claim %q", claim)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("the delegation claim %q must be a non-empty string", claim)
	}
	return text, nil
}

func delegationTime(body map[string]any, claim string) (int64, bool, error) {
	value, present := body[claim]
	if !present {
		return 0, false, nil
	}
	seconds, ok := value.(float64)
	if !ok {
		return 0, false, fmt.Errorf("the delegation claim %q must be a number", claim)
	}
	if seconds < 0 {
		return 0, false, fmt.Errorf("the delegation claim %q must not be negative", claim)
	}
	if seconds >= maxDelegationNumericDate {
		return 0, false, fmt.Errorf("the delegation claim %q is outside the representable range", claim)
	}
	return int64(seconds), true, nil
}

func splitDelegation(ctx context.Context, cfg model.Configuration, mark model.TrustMark) ([]string, error) {
	parts := strings.Split(*mark.DelegationJWT, ".")
	if len(parts) != 3 {
		cfg.LogError(ctx, "the trust mark's delegation is not a signed JWT", slog.Int("parts_count", len(parts)), slog.String("trust_mark_type", model.TruncateForResponse(mark.Type)))
		return nil, fmt.Errorf("the trust mark's delegation is not a signed JWT")
	}
	return parts, nil
}

func verifyDelegation(ctx context.Context, cfg model.Configuration, mark model.TrustMark, issuer model.EntityIdentifier, owner model.TrustMarkOwner) error {
	delegation := *mark.DelegationJWT

	parts, err := splitDelegation(ctx, cfg, mark)
	if err != nil {
		return err
	}

	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		cfg.LogError(ctx, "failed to decode the delegation header", slog.String("error", err.Error()))
		return fmt.Errorf("the trust mark's delegation has a header that cannot be decoded")
	}
	var head map[string]any
	if err := json.Unmarshal(headBytes, &head); err != nil {
		cfg.LogError(ctx, "failed to unmarshal the delegation header", slog.String("error", model.TruncateForResponse(err.Error())))
		return fmt.Errorf("the trust mark's delegation has a header that is not a JSON object")
	}

	typ, ok := head["typ"].(string)
	if !ok || !namesDelegationType(typ) {
		cfg.LogError(ctx, "the delegation is not explicitly typed as a trust mark delegation", slog.String("typ", describeHeaderMember(head["typ"])))
		return fmt.Errorf("the trust mark's delegation must carry a 'typ' header of %q", delegationJWTType)
	}

	algorithm, ok := head["alg"].(string)
	if !ok || algorithm == "" || algorithm == "none" {
		cfg.LogError(ctx, "the delegation does not name an acceptable signing algorithm", slog.String("alg", describeHeaderMember(head["alg"])))
		return fmt.Errorf("the trust mark's delegation must carry an 'alg' header naming a signing algorithm, and it must not be 'none'")
	}
	kid, ok := head["kid"].(string)
	if !ok || kid == "" {
		cfg.LogError(ctx, "the delegation is missing a usable 'kid' header", slog.String("kid", describeHeaderMember(head["kid"])))
		return fmt.Errorf("the trust mark's delegation must carry a 'kid' header naming the signing key")
	}

	bodyBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		cfg.LogError(ctx, "failed to decode the delegation body", slog.String("error", err.Error()))
		return fmt.Errorf("the trust mark's delegation has a body that cannot be decoded")
	}
	var body map[string]any
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		cfg.LogError(ctx, "failed to unmarshal the delegation body", slog.String("error", model.TruncateForResponse(err.Error())))
		return fmt.Errorf("the trust mark's delegation has a body that is not a JSON object")
	}

	delegatedIssuer, err := delegationClaim(body, "sub")
	if err != nil {
		cfg.LogError(ctx, "the delegation has no usable 'sub' claim", slog.String("error", err.Error()))
		return err
	}
	if delegatedIssuer != string(issuer) {
		cfg.LogError(ctx, "the delegation does not name the trust mark issuer as its subject", slog.String("delegation_sub", model.TruncateForResponse(delegatedIssuer)), slog.String("issuer", string(issuer)))
		return fmt.Errorf("the trust mark's delegation names a different entity as its subject than the issuer of the trust mark")
	}

	delegatingOwner, err := delegationClaim(body, "iss")
	if err != nil {
		cfg.LogError(ctx, "the delegation has no usable 'iss' claim", slog.String("error", err.Error()))
		return err
	}
	if delegatingOwner != string(owner.Sub) {
		cfg.LogError(ctx, "the delegation was not issued by the owner the trust anchor names", slog.String("delegation_iss", model.TruncateForResponse(delegatingOwner)), slog.String("owner", string(owner.Sub)))
		return fmt.Errorf("the trust mark's delegation was not issued by the owner the trust anchor names for this trust mark type")
	}

	delegatedType, err := delegationClaim(body, "trust_mark_type")
	if err != nil {
		cfg.LogError(ctx, "the delegation has no usable 'trust_mark_type' claim", slog.String("error", err.Error()))
		return err
	}
	if delegatedType != mark.Type {
		cfg.LogError(ctx, "the delegation is for a different trust mark type", slog.String("delegation_type", model.TruncateForResponse(delegatedType)), slog.String("trust_mark_type", model.TruncateForResponse(mark.Type)))
		return fmt.Errorf("the trust mark's delegation is for a different trust mark type than the trust mark itself")
	}

	issuedAt, present, err := delegationTime(body, "iat")
	if err != nil {
		cfg.LogError(ctx, "the delegation has a malformed 'iat' claim", slog.String("error", err.Error()))
		return err
	}
	if !present {
		cfg.LogError(ctx, "the delegation is missing the required 'iat' claim")
		return fmt.Errorf("the trust mark's delegation is missing the required claim \"iat\"")
	}
	if issuedAt > time.Now().Add(model.ClockSkewLeeway).UTC().Unix() {
		cfg.LogError(ctx, "the delegation is not yet issued", slog.Int64("iat", issuedAt))
		return fmt.Errorf("the trust mark's delegation names an issuance time that has not yet arrived")
	}

	expiry, present, err := delegationTime(body, "exp")
	if err != nil {
		cfg.LogError(ctx, "the delegation has a malformed 'exp' claim", slog.String("error", err.Error()))
		return err
	}
	if present && time.Now().Add(-model.ClockSkewLeeway).UTC().Unix() > expiry {
		cfg.LogError(ctx, "the delegation has expired", slog.Int64("exp", expiry))
		return fmt.Errorf("the trust mark's delegation has expired")
	}

	selectedKeys := selectOwnerKeys(ctx, cfg, owner, kid)
	if len(selectedKeys) == 0 {
		cfg.LogError(ctx, "the delegation names a key the owner does not publish", slog.String("kid", model.TruncateForResponse(kid)), slog.String("owner", string(owner.Sub)))
		return fmt.Errorf("the trust mark's delegation names a 'kid' the trust mark owner does not publish a usable key for")
	}

	unusable := 0
	for _, selectedKey := range selectedKeys {
		if err := entity_statement.VerifySelectedKey(delegation, selectedKey); err != nil {
			cfg.LogError(ctx, "an owner key named by the delegation cannot verify it", slog.String("kid", model.TruncateForResponse(kid)), slog.String("owner", string(owner.Sub)), slog.String("error", model.TruncateForResponse(err.Error())))
			unusable++
			continue
		}

		if _, _, err := jwt.Validate(delegation, func() ([]crypto.PublicKey, error) {
			publicKey, err := jwk.PublicFromJwk(selectedKey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse the owner's JWK as a public key: %w", err)
			}
			return []crypto.PublicKey{publicKey}, nil
		}, &josemodel.JoseOptions{UseTokenProvidedKeys: false, ClockSkewLeeway: model.ClockSkewLeeway}); err != nil {
			cfg.LogError(ctx, "the delegation signature does not verify against an owner key", slog.String("kid", model.TruncateForResponse(kid)), slog.String("owner", string(owner.Sub)), slog.String("error", model.TruncateForResponse(err.Error())))
			continue
		}

		return nil
	}

	if unusable == len(selectedKeys) {
		return fmt.Errorf("the trust mark's delegation names a key the trust mark owner publishes that cannot verify it")
	}
	return fmt.Errorf("the trust mark's delegation signature does not verify against the key the trust mark owner publishes")
}

func verifyDelegationRequirement(ctx context.Context, cfg model.Configuration, mark model.TrustMark, issuer model.EntityIdentifier, owners map[string]model.TrustMarkOwner) error {
	owner, owned := owners[mark.Type]

	if mark.DelegationJWT == nil {
		if owned {
			cfg.LogError(ctx, "the trust anchor names an owner for this trust mark type, so the trust mark must carry a delegation", slog.String("trust_mark_type", model.TruncateForResponse(mark.Type)), slog.String("owner", string(owner.Sub)))
			return fmt.Errorf("the trust anchor names an owner for this trust mark type, so the trust mark must carry a 'delegation' claim")
		}
		return nil
	}

	if _, err := splitDelegation(ctx, cfg, mark); err != nil {
		return err
	}

	if !owned {
		cfg.LogError(ctx, "the trust mark carries a delegation for a type the trust anchor names no owner for, so there are no owner keys to verify it against", slog.String("trust_mark_type", model.TruncateForResponse(mark.Type)))
		return fmt.Errorf("the trust mark carries a 'delegation' claim for a type the trust anchor names no owner for, so there is no key to verify it against")
	}

	return verifyDelegation(ctx, cfg, mark, issuer, owner)
}
