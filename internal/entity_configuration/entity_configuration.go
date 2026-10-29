package entity_configuration

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Retrieve(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier, cache *resolvecache.Cache) (*string, *model.EntityStatement, error) {
	if signed, statement, ok := cache.Load(entityIdentifier); ok {
		cfg.LogInfo(ctx, "serving entity configuration from resolve cache", slog.String("subject", string(entityIdentifier)))
		return signed, statement, nil
	}

	if fetched := cache.RecordFetch(); fetched > cfg.EntitiesTraversedLimit() {
		cfg.LogError(ctx, "reached the maximum number of entity configurations one request may fetch", slog.String("subject", string(entityIdentifier)), slog.Int("fetched", fetched), slog.Int("max_entities", cfg.EntitiesTraversedLimit()))
		return nil, nil, model.NewLimitReachedError("the resolver reached the maximum number of entity configurations it may fetch for one request")
	}

	if held := cache.PeerBytes(); held > cfg.RequestPeerBytesLimit() {
		cfg.LogError(ctx, "reached the maximum bytes of peer statements one request may hold", slog.String("subject", string(entityIdentifier)), slog.Int64("held", held), slog.Int64("max_bytes", cfg.RequestPeerBytesLimit()))
		return nil, nil, model.NewLimitReachedError("the resolver reached the maximum bytes of peer statements it may hold for one request")
	}

	signed, statement, err := fetch(ctx, cfg, entityIdentifier)
	if err != nil {
		return nil, nil, err
	}
	if signed != nil {
		cache.RecordPeerBytes(model.StatementCost(*signed, statement))
	}
	cache.Store(entityIdentifier, signed, statement)
	return signed, statement, nil
}

func fetch(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	if cfg.HttpClient == nil {
		return nil, nil, model.NewServerError("no http client present")
	}

	cfg.LogInfo(ctx, "retrieving entity configuration", slog.String("subject", string(entityIdentifier)))
	fetchCtx, cancel := context.WithTimeout(ctx, cfg.PeerResponseTimeLimit())
	defer cancel()

	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, fmt.Sprintf("%s.well-known/openid-federation", strings.TrimSuffix(string(entityIdentifier), "/")+"/"), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/entity-statement+jwt")

	response, err := cfg.HttpClient.Do(request)
	if err != nil {
		if ended := fetchEnded(ctx, fetchCtx, entityIdentifier); ended != nil {
			return nil, nil, ended
		}
		return nil, nil, err
	}
	defer response.Body.Close() //nolint:errcheck

	if err := fetchEnded(ctx, fetchCtx, entityIdentifier); err != nil {
		return nil, nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("non-200 response from %q's entity configuration: %s", entityIdentifier, model.TruncateForResponse(response.Status))
	}
	cfg.LogInfo(ctx, "entity configuration retrieved", slog.String("subject", string(entityIdentifier)))

	if !strings.Contains(response.Header.Get("Content-Type"), "application/entity-statement+jwt") { //todo: check on this - not sure if it has to be an exact match or not...
		return nil, nil, fmt.Errorf("invalid Content-Type response from %q's entity configuration: %s", entityIdentifier, model.TruncateForResponse(response.Header.Get("Content-Type")))
	}

	limit := cfg.PeerResponseLimit()
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %q's entity configuration response body: %s", entityIdentifier, err.Error())
	}
	if err := fetchEnded(ctx, fetchCtx, entityIdentifier); err != nil {
		return nil, nil, err
	}
	if int64(len(responseBytes)) > limit {
		return nil, nil, fmt.Errorf("%q's entity configuration exceeded the %d byte response limit", entityIdentifier, limit)
	}

	entityConfiguration, err := Validate(ctx, cfg, entityIdentifier, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	return josemodel.Pointer(string(responseBytes)), entityConfiguration, nil
}

func Validate(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier, entityConfigurationJwt string) (*model.EntityStatement, error) {
	entityConfiguration, err := validate(ctx, cfg, entityIdentifier, entityConfigurationJwt)
	if err != nil {
		if errors.Is(err, model.ErrInvalidMetadata) || errors.Is(err, model.ErrInvalidTrustChain) {
			return nil, err
		}
		return nil, model.NewInvalidTrustChainError(err.Error())
	}
	return entityConfiguration, nil
}

func validate(ctx context.Context, cfg model.Configuration, entityIdentifier model.EntityIdentifier, entityConfigurationJwt string) (*model.EntityStatement, error) {
	parts := strings.Split(entityConfigurationJwt, ".")
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

	jwks, ok := bodyMap["jwks"]
	if !ok {
		return nil, fmt.Errorf("missing required body claim 'jwks'")
	}

	parsedJwks, err := model.ParseFederationEntityKeys(jwks)
	if err != nil {
		return nil, fmt.Errorf("the 'jwks' claim %s", err.Error())
	}

	if err = entity_statement.VerifyAgainstJwks(ctx, entityConfigurationJwt, sKid, parsedJwks); err != nil {
		return nil, err
	}

	for _, claim := range []string{"metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint"} {
		if _, present := bodyMap[claim]; present {
			return nil, model.NewInvalidTrustChainError(fmt.Sprintf("the %q claim is permitted only in subordinate statements, not in an entity configuration", claim))
		}
	}

	var entityConfiguration model.EntityStatement
	err = json.Unmarshal(body, &entityConfiguration)
	if err != nil {
		if errors.Is(err, model.ErrInvalidMetadata) {
			return nil, fmt.Errorf("invalid entity statement: %w", err)
		}
		return nil, model.NewInvalidTrustChainError(fmt.Sprintf("invalid entity statement: %s", err.Error()))
	}

	if entityConfiguration.Iss != entityConfiguration.Sub {
		return nil, model.NewInvalidTrustChainError("'iss' and 'sub' claims do not match")
	}

	if entityConfiguration.Iss != entityIdentifier {
		return nil, fmt.Errorf("'iss' claim does not match the original entity identifier")
	}

	if entityConfiguration.Sub != entityIdentifier {
		return nil, fmt.Errorf("'sub' claim does not match the original entity identifier")
	}

	model.LogPrivateKeyMembersInRawSet(ctx, &cfg, entityConfiguration.Sub, entityConfiguration.Sub, jwks)

	if entityConfiguration.Metadata != nil {
		if err = entityConfiguration.Metadata.Verify(cfg.EntityTypes, cfg.DiscardUnrecognisedEntityTypes); err != nil {
			return nil, model.NewInvalidMetadataError(err.Error())
		}
	}

	return &entityConfiguration, nil
}

const signingFailureError = "unable to produce the entity configuration at this time"

// New takes a given configuration struct and produces a signed Entity Configuration
func New(ctx context.Context, cfg model.ServerConfiguration) (*string, error) {
	entityConfiguration := cfg.EntityConfiguration
	entityConfiguration.Sub = cfg.EntityIdentifier
	entityConfiguration.Iss = cfg.EntityIdentifier
	entityConfiguration.AuthorityHints = cfg.AuthorityHints
	entityConfiguration.TrustMarks = cfg.TrustMarks
	entityConfiguration.Iat = time.Now().UTC().Unix()
	entityConfigurationLifetime, err := model.ResolveStatementLifetime("EntityConfigurationLifetime", cfg.EntityConfigurationLifetime, model.DefaultEntityConfigurationLifetime)
	if err != nil {
		return nil, err
	}
	entityConfiguration.Exp = time.Now().Add(entityConfigurationLifetime).UTC().Unix()
	entityConfiguration.MetadataPolicy = nil
	entityConfiguration.Constraints = nil
	entityConfiguration.SourceEndpoint = nil

	metadata := model.Metadata{}
	if cfg.EntityConfiguration.Metadata != nil {
		metadata = *cfg.EntityConfiguration.Metadata
	}

	federationMetadata := model.FederationMetadata{}
	if metadata.FederationMetadata != nil {
		for claim, value := range *metadata.FederationMetadata {
			federationMetadata[claim] = value
		}
	}

	trimmed := strings.TrimSuffix(string(cfg.EntityIdentifier), "/")

	if cfg.IntermediateConfiguration != nil {
		federationMetadata["federation_fetch_endpoint"] = trimmed + "/fetch"
		federationMetadata["federation_list_endpoint"] = trimmed + "/list"
		federationMetadata["federation_resolve_endpoint"] = trimmed + "/resolve"
		if cfg.Extensions.ExtendedListing.Enabled {
			federationMetadata["federation_extended_list_endpoint"] = trimmed + "/extended-list"
		}
		if cfg.Extensions.SubordinateStatus.Enabled {
			federationMetadata["federation_subordinate_events_endpoint"] = trimmed + "/subordinate-status"
		}
	}

	if cfg.TrustMarkRetriever != nil {
		federationMetadata["federation_trust_mark_status_endpoint"] = trimmed + "/trust-mark-status"
		federationMetadata["federation_trust_mark_list_endpoint"] = trimmed + "/trust-mark-list"
		federationMetadata["federation_trust_mark_endpoint"] = trimmed + "/trust-mark"
	}

	if len(federationMetadata) > 0 || metadata.FederationMetadata != nil {
		metadata.FederationMetadata = &federationMetadata
	}
	if cfg.EntityConfiguration.Metadata != nil || len(federationMetadata) > 0 {
		entityConfiguration.Metadata = &metadata
	}

	if cfg.SignerConfiguration.KeyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	publicJWK, err := jwk.PublicJwk(cfg.SignerConfiguration.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to convert provided signer public key to a jwk: %s", err.Error())
	}
	(*publicJWK)["kid"] = cfg.SignerConfiguration.KeyID
	(*publicJWK)["alg"] = cfg.SignerConfiguration.Algorithm

	jwks := josemodel.Jwks{}
	jwks.Opts.EnforceUniqueKIDs = true
	seen := map[string]struct{}{}
	for _, key := range cfg.EntityConfiguration.JWKs.Keys {
		kid, ok := key["kid"]
		if !ok {
			return nil, fmt.Errorf("all provided jwk values in entity cfg must have a `kid` claim - missing from one or more")
		}
		sKid, ok := kid.(string)
		if !ok {
			return nil, fmt.Errorf("one or more provided jwk values have a malformed `kid` claim")
		}
		if _, duplicate := seen[sKid]; duplicate {
			return nil, fmt.Errorf("all provided jwk values in entity cfg must have unique `kid` claims - %q appears more than once", sKid)
		}
		if err := model.ValidateJWKShape(key); err != nil {
			return nil, fmt.Errorf("the provided jwk value with key ID %q %s", model.TruncateForResponse(sKid), err.Error())
		}
		if err := model.VerifyPublishableJWK(key); err != nil {
			return nil, fmt.Errorf("refusing to publish the jwk value with key ID %q because it %s", model.TruncateForResponse(sKid), err.Error())
		}
		if err := model.ValidateKeyOps(key); err != nil {
			return nil, fmt.Errorf("the provided jwk value with key ID %q %s", model.TruncateForResponse(sKid), err.Error())
		}
		if declared, ok := key["alg"].(string); ok {
			if err := model.VerifyKeyStrength(key, declared); err != nil {
				return nil, fmt.Errorf("the provided jwk value with key ID %q %s", model.TruncateForResponse(sKid), err.Error())
			}
		} else if err := model.VerifyKeyStrengthForAnySignatureAlgorithm(key); err != nil {
			return nil, fmt.Errorf("the provided jwk value with key ID %q %s", model.TruncateForResponse(sKid), err.Error())
		}
		seen[sKid] = struct{}{}
		jwks.Keys = append(jwks.Keys, key)
	}

	if existing, _ := jwks.RetrieveByKeyID(cfg.SignerConfiguration.KeyID); len(existing) > 0 {
		if err := publishedKeyUsableForSigning(existing[0], *publicJWK, cfg.SignerConfiguration.Signer.Public()); err != nil {
			return nil, fmt.Errorf("a configured jwk uses the signing key ID %q but %s, so the issued statement could not be verified", cfg.SignerConfiguration.KeyID, err.Error())
		}
	} else {
		jwks.Keys = append(jwks.Keys, *publicJWK)
	}

	if cfg.IntermediateConfiguration != nil {
		subordinateSignerConfigurations, err := cfg.GetSubordinateJWKs(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get subordinate signer configurations: %s", err.Error())
		}
		for _, signerConfiguration := range subordinateSignerConfigurations {
			apkJWK, err := jwk.PublicJwk(signerConfiguration.Signer.Public())
			if err != nil {
				return nil, fmt.Errorf("failed to convert override signer public key to a jwk: %s", err.Error())
			}
			(*apkJWK)["kid"] = signerConfiguration.KeyID
			(*apkJWK)["alg"] = signerConfiguration.Algorithm

			if err := model.VerifyKeyStrength(*apkJWK, signerConfiguration.Algorithm); err != nil {
				cfg.LogError(ctx, "not publishing a subordinate signer key because its modulus is outside the sizes this library verifies for the algorithm it signs with, so statements it signs cannot be verified", slog.String("kid", model.TruncateForResponse(signerConfiguration.KeyID)), slog.String("error", err.Error()))
				continue
			}

			if existing, _ := jwks.RetrieveByKeyID(signerConfiguration.KeyID); len(existing) > 0 {
				if err := publishedKeyUsableForSigning(existing[0], *apkJWK, signerConfiguration.Signer.Public()); err != nil {
					return nil, fmt.Errorf("subordinate signer key ID %q is already published but %s, so statements signed with it could not be verified", signerConfiguration.KeyID, err.Error())
				}
				continue
			}
			if err := jwks.Add(*apkJWK); err != nil {
				return nil, fmt.Errorf("failed to publish subordinate signer key %q: %s", signerConfiguration.KeyID, err.Error())
			}
		}
	}

	entityConfiguration.JWKs = jwks

	if cfg.TrustMarkIssuerRetriever != nil {
		trustMarkIssuerMap, err := cfg.TrustMarkIssuerRetriever.ListTrustMarkIssuers(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list trust mark issuers: %s", err.Error())
		}
		trustMarkIssuers := make(map[string][]model.EntityIdentifier, len(trustMarkIssuerMap))
		for trustMarkType, issuers := range trustMarkIssuerMap {
			if issuers == nil {
				issuers = []model.EntityIdentifier{}
			}
			trustMarkIssuers[trustMarkType] = issuers
		}
		entityConfiguration.TrustMarkIssuers = trustMarkIssuers
	}

	entityConfigurationBytes, err := json.Marshal(entityConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize entity cfg: %s", err.Error())
	}

	var entityConfigurationMap map[string]any
	err = json.Unmarshal(entityConfigurationBytes, &entityConfigurationMap)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize entity cfg: %s", err.Error())
	}

	if err = model.VerifyPublishableStatementKeys(entityConfigurationMap); err != nil {
		return nil, fmt.Errorf("refusing to publish this entity configuration because %s", err.Error())
	}

	for _, trustMarkType := range slices.Sorted(maps.Keys(entityConfiguration.TrustMarkOwners)) {
		usable := slices.ContainsFunc(entityConfiguration.TrustMarkOwners[trustMarkType].JWKs.Keys, func(key map[string]any) bool {
			return model.ValidateJWKShape(key) == nil
		})
		if !usable {
			return nil, fmt.Errorf("refusing to publish this entity configuration because the trust_mark_owners entry for %q holds no usable key, so no delegation for that type could be verified", model.TruncateForResponse(trustMarkType))
		}
	}

	if err = model.VerifyIssuedStatement(entityConfigurationBytes, cfg.EntityTypes); err != nil {
		return nil, fmt.Errorf("refusing to publish an entity configuration this implementation would reject: %s", err.Error())
	}

	if jwa.GetAlgorithm(cfg.SignerConfiguration.Algorithm) == jwa.Unknown {
		return nil, fmt.Errorf("refusing to publish an entity configuration this implementation would reject: %q is not a supported signing algorithm", cfg.SignerConfiguration.Algorithm)
	}

	token, err := jwt.New(cfg.SignerConfiguration.Signer, map[string]any{
		"kid": cfg.SignerConfiguration.KeyID,
		"typ": "entity-statement+jwt",
		"alg": cfg.SignerConfiguration.Algorithm,
	}, entityConfigurationMap, jwt.Opts{Algorithm: jwa.GetAlgorithm(cfg.SignerConfiguration.Algorithm)})
	if err != nil {
		if errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || errors.Is(err, joseerror.ErrInvalidPrivateKey) {
			return nil, fmt.Errorf("refusing to publish an entity configuration this implementation would reject: %s", err.Error())
		}
		cfg.LogError(ctx, "the signer could not sign the entity configuration", slog.String("error", model.TruncateForResponse(err.Error())))
		return nil, model.ClassifySignerError(err, signingFailureError)
	}

	if err = entity_statement.VerifyIssuedSignature(ctx, *token, cfg.SignerConfiguration.KeyID, cfg.SignerConfiguration.Algorithm, cfg.SignerConfiguration.Signer); err != nil {
		return nil, fmt.Errorf("refusing to publish an entity configuration this implementation would reject: %s", err.Error())
	}

	return token, nil
}

type publicKeyComparer interface {
	Equal(crypto.PublicKey) bool
}

func publishedKeyUsableForSigning(existing, intended map[string]any, signerPublicKey crypto.PublicKey) error {
	if err := model.ValidateJWKShape(existing); err != nil {
		return err
	}

	publishedKey, err := jwk.PublicFromJwk(existing)
	if err != nil {
		return fmt.Errorf("is not a usable jwk: %s", err.Error())
	}
	comparer, ok := publishedKey.(publicKeyComparer)
	if !ok || !comparer.Equal(signerPublicKey) {
		return fmt.Errorf("holds different key material")
	}

	if use, present := existing["use"]; present {
		if sUse, ok := use.(string); !ok || sUse != "sig" {
			return fmt.Errorf("declares a 'use' of %v rather than \"sig\"", use)
		}
	}
	if !model.KeyOpsPermitVerify(existing) {
		return fmt.Errorf("declares 'key_ops' without \"verify\"")
	}
	if alg, present := existing["alg"]; present {
		if alg != intended["alg"] {
			return fmt.Errorf("declares an 'alg' of %v rather than %v", alg, intended["alg"])
		}
	}
	return nil
}

func fetchEnded(ctx, fetchCtx context.Context, entityIdentifier model.EntityIdentifier) error {
	if fetchCtx.Err() == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("stopped fetching %q's entity configuration: %s", entityIdentifier, ctxErr.Error())
	}
	return fmt.Errorf("%q's entity configuration did not arrive within the peer deadline: %s", entityIdentifier, fetchCtx.Err().Error())
}
