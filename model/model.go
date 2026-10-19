package model

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

type Configuration struct {
	HttpClient *http.Client
	Logger     *slog.Logger

	// EntityTypes registers Entity Types beyond those built in. Entries are merged over the
	// built-in definitions, so registering under a built-in identifier replaces it.
	EntityTypes EntityTypeRegistry

	// DiscardUnrecognisedEntityTypes removes Entity Types absent from EntityTypes during
	// verification. When false, unrecognised Entity Types are preserved and relayed untouched.
	DiscardUnrecognisedEntityTypes bool

	// MaxTrustChainDepth bounds how many entities the resolver will traverse from the leaf
	// while walking authority_hints to reach a Trust Anchor. Zero (the default) means
	// unlimited. This is an operational safeguard against hostile or misconfigured
	// authority_hints graphs and is independent of the spec's per-statement max_path_length
	// constraint; set it according to how deep legitimate Trust Chains are in your federation
	// (a tightly walled-garden federation can set a low value, an open one may leave it unset).
	MaxTrustChainDepth int

	MaxPeerResponseBytes int64

	MaxTrustMarkIssuers int
}

const DefaultMaxPeerResponseBytes int64 = 1 << 20

const (
	DefaultEntityConfigurationLifetime  = time.Hour
	DefaultSubordinateStatementLifetime = time.Hour
)

const DefaultMaxTrustMarkIssuers = 64

func (cfg *Configuration) TrustMarkIssuerLimit() int {
	if cfg.MaxTrustMarkIssuers > 0 {
		return cfg.MaxTrustMarkIssuers
	}
	return DefaultMaxTrustMarkIssuers
}

func (cfg *Configuration) PeerResponseLimit() int64 {
	limit := cfg.MaxPeerResponseBytes
	if limit <= 0 {
		limit = DefaultMaxPeerResponseBytes
	}
	if limit > math.MaxInt64-1 {
		limit = math.MaxInt64 - 1
	}
	return limit
}

func (cfg *Configuration) LogInfo(ctx context.Context, msg string, args ...any) {
	if cfg.Logger != nil {
		cfg.Logger.InfoContext(ctx, msg, args...)
	}
}

func (cfg *Configuration) LogError(ctx context.Context, msg string, args ...any) {
	if cfg.Logger != nil {
		cfg.Logger.ErrorContext(ctx, msg, args...)
	}
}

type ServerConfiguration struct {
	Configuration
	SignerConfiguration         SignerConfiguration
	EntityIdentifier            EntityIdentifier
	AuthorityHints              []EntityIdentifier
	TrustMarks                  []TrustMarkHolder
	EntityConfiguration         EntityStatement
	EntityConfigurationLifetime time.Duration
	IntermediateConfiguration   *IntermediateConfiguration
	Extensions                  Extensions
	MetadataRetriever           Retriever
	TrustMarkIssuerRetriever    TrustMarkIssuerRetriever
	TrustMarkRetriever          TrustMarkRetriever
	EntityIdentifierResolver    EntityIdentifierResolver
}

type ClientConfiguration struct {
	Configuration
}

func (cfg *ServerConfiguration) GetSubordinates(ctx context.Context) (map[EntityIdentifier]*SubordinateConfiguration, error) {
	if cfg.MetadataRetriever != nil {
		return cfg.MetadataRetriever.GetSubordinates(ctx)
	}
	i := cfg.IntermediateConfiguration
	i.mu.RLock()
	defer i.mu.RUnlock()
	subordinates := make(map[EntityIdentifier]*SubordinateConfiguration, len(i.subordinates))
	for identifier, subordinate := range i.subordinates {
		subordinates[identifier] = subordinate
	}
	return subordinates, nil
}

func (cfg *ServerConfiguration) GetSubordinateJWKs(ctx context.Context) ([]SignerConfiguration, error) {
	if cfg.MetadataRetriever != nil {
		return cfg.MetadataRetriever.GetSubordinateSigners(ctx)
	}

	var signers []SignerConfiguration

	subordinates, err := cfg.GetSubordinates(ctx)
	if err != nil {
		return nil, err
	}
	for _, subordinateConfiguration := range subordinates {
		if subordinateConfiguration == nil {
			continue
		}
		if subordinateConfiguration.SignerConfiguration != nil {
			signers = append(signers, *subordinateConfiguration.SignerConfiguration)
		}
	}
	return signers, nil
}

func (cfg *ServerConfiguration) GetSubordinate(ctx context.Context, identifier EntityIdentifier) (*SubordinateConfiguration, error) {
	i := cfg.IntermediateConfiguration

	i.mu.RLock()
	cached := i.subordinates[identifier]
	i.mu.RUnlock()

	if cached != nil && time.Now().UTC().Before(time.Unix(cached.CachedAt, 0).Add(i.SubordinateCacheTime).UTC()) {
		return cached, nil
	}

	if cfg.MetadataRetriever == nil {
		return nil, NewNotFoundError(fmt.Sprintf("subordinate entity %s not found", identifier))
	}

	entity, err := cfg.MetadataRetriever.GetSubordinate(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, NewNotFoundError(fmt.Sprintf("subordinate entity %s not found", identifier))
	}

	stored := *entity
	stored.CachedAt = time.Now().UTC().Unix()

	i.mu.Lock()
	if i.subordinates == nil {
		i.subordinates = map[EntityIdentifier]*SubordinateConfiguration{}
	}
	i.subordinates[identifier] = &stored
	i.mu.Unlock()

	return &stored, nil
}

type Retriever interface {
	GetSubordinate(ctx context.Context, identifier EntityIdentifier) (*SubordinateConfiguration, error)
	GetSubordinates(ctx context.Context) (map[EntityIdentifier]*SubordinateConfiguration, error)
	GetSubordinateSigners(ctx context.Context) ([]SignerConfiguration, error)
}

type SubordinateListingFilter struct {
	EntityTypes   []string
	TrustMarked   *bool
	TrustMarkType *string
	Intermediate  *bool
}

func (f SubordinateListingFilter) IsEmpty() bool {
	return len(f.EntityTypes) == 0 && f.TrustMarked == nil && f.TrustMarkType == nil && f.Intermediate == nil
}

type SubordinateListingRetriever interface {
	ListSubordinates(ctx context.Context, filter SubordinateListingFilter) ([]EntityIdentifier, error)
}

type TrustMarkIssuerRetriever interface {
	ListTrustMarkIssuers(ctx context.Context) (map[string][]EntityIdentifier, error)
}

type TrustMarkRetriever interface {
	GetTrustMarkStatus(ctx context.Context, trustMark string) (*string, error)
	IssueTrustMark(ctx context.Context, trustMarkIdentifier string, entityIdentifier EntityIdentifier) (*string, error)
	ListTrustMarks(ctx context.Context, trustMarkIdentifier string, identifier *EntityIdentifier) ([]EntityIdentifier, error)
}

type ExtendedListingFilter struct {
	EntityTypes   []string
	TrustMarked   *bool
	TrustMarkType []string
	Intermediate  *bool
	From          *string
	Limit         int
	Claims        []string
}

func (f ExtendedListingFilter) IsEmpty() bool {
	return len(f.EntityTypes) == 0 && f.TrustMarked == nil && len(f.TrustMarkType) == 0 && f.Intermediate == nil
}

type ExtendedListingRetriever interface {
	GetExtendedSubordinates(ctx context.Context, filter ExtendedListingFilter) (*ExtendedListingResponse, error)
}

type SubordinateStatusRetriever interface {
	GetSubordinateStatus(ctx context.Context, sub EntityIdentifier) (*SubordinateStatusResponse, error)
}

type Extensions struct {
	ExtendedListing   ExtendedListingConfiguration
	SubordinateStatus SubordinateStatusConfiguration
}

type SubordinateStatusConfiguration struct {
	Enabled           bool
	ResponseLifetime  *time.Duration
	MetadataRetriever SubordinateStatusRetriever
}

type ExtendedListingConfiguration struct {
	Enabled           bool
	SizeLimit         int
	MetadataRetriever ExtendedListingRetriever
}

type IntermediateConfiguration struct {
	mu                           sync.RWMutex
	subordinates                 map[EntityIdentifier]*SubordinateConfiguration
	SubordinateStatementLifetime time.Duration
	SubordinateCacheTime         time.Duration
}

func (i *IntermediateConfiguration) FlushCache() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.subordinates = map[EntityIdentifier]*SubordinateConfiguration{}
}

func (i *IntermediateConfiguration) AddSubordinate(identifier EntityIdentifier, subordinateConfiguration *SubordinateConfiguration) {
	if subordinateConfiguration == nil {
		return
	}
	stored := *subordinateConfiguration
	stored.JWKs.Opts.EnforceUniqueKIDs = true
	stored.CachedAt = time.Now().UTC().Unix()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.subordinates == nil {
		i.subordinates = map[EntityIdentifier]*SubordinateConfiguration{}
	}
	i.subordinates[identifier] = &stored
}

type SubordinateConfiguration struct {
	CachedAt            int64
	Policies            MetadataPolicy
	JWKs                josemodel.Jwks
	SignerConfiguration *SignerConfiguration // SignerConfiguration allows consumers to specify override private key material for a given subordinate entity
}

type SignerConfiguration struct {
	Signer           crypto.Signer
	KeyID, Algorithm string
}

type ExtendedListingResponse struct { //todo: change immediate subordinate entities to be a defined struct
	ImmediateSubordinateEntities []map[string]any `json:"immediate_subordinate_entities"`
	Next                         *string          `json:"next,omitempty"`
}

type SubordinateStatusResponse struct {
	Events []SubordinateStatusEvent `json:"federation_registration_events"`
}

type SubordinateStatusEvent struct {
	Iat              int64   `json:"iat"`
	Event            string  `json:"event"`
	EventDescription *string `json:"event_description,omitempty"`
}

type EntityStatement struct { //todo: allow for additional claims to be set - think profiles
	Iss              EntityIdentifier              `json:"iss"`
	Sub              EntityIdentifier              `json:"sub"`
	Iat              int64                         `json:"iat"`
	Exp              int64                         `json:"exp"`
	JWKs             josemodel.Jwks                `json:"jwks"`
	AuthorityHints   []EntityIdentifier            `json:"authority_hints,omitempty"`
	TrustAnchorHints []EntityIdentifier            `json:"trust_anchor_hints,omitempty"`
	Metadata         *Metadata                     `json:"metadata,omitempty"`
	MetadataPolicy   *MetadataPolicy               `json:"metadata_policy,omitempty"`
	Constraints      any                           `json:"constraints,omitempty"` //todo
	TrustMarks       []TrustMarkHolder             `json:"trust_marks,omitempty"`
	TrustMarkIssuers map[string][]EntityIdentifier `json:"trust_mark_issuers,omitempty"`
	TrustMarkOwners  map[string]TrustMarkOwner     `json:"trust_mark_owners,omitempty"`
	SourceEndpoint   *string                       `json:"source_endpoint,omitempty"`
}

type TrustMarkOwner struct {
	Sub              EntityIdentifier `json:"sub"`
	JWKs             josemodel.Jwks   `json:"jwks"`
	AdditionalClaims map[string]any   `json:"-"`
}

func (t TrustMarkOwner) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(t.AdditionalClaims)+2)
	for claim, value := range t.AdditionalClaims {
		out[claim] = value
	}
	out["sub"] = t.Sub
	out["jwks"] = t.JWKs
	return json.Marshal(out)
}

const ClockSkewLeeway = 60 * time.Second

const maxNumericDate = float64(1 << 62)

var entityStatementClaims = []string{
	"iss", "sub", "iat", "exp", "jwks", "aud", "crit",
	"authority_hints", "trust_anchor_hints", "metadata", "metadata_policy",
	"metadata_policy_crit", "constraints", "trust_marks", "trust_mark_issuers",
	"trust_mark_owners", "source_endpoint",
}

var standardPolicyOperators = []string{
	"value", "add", "default", "one_of", "subset_of", "superset_of", "essential",
}

func parseEntityIdentifierArray(claim string, value any) ([]EntityIdentifier, error) {
	entries, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("'%s' claim is malformed", claim)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("'%s' claim must not be the empty array", claim)
	}
	parsed := make([]EntityIdentifier, 0, len(entries))
	for _, entry := range entries {
		sEntry, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("'%s' claim contains malformed entity identifier", claim)
		}
		entityIdentifier, err := ValidateEntityIdentifier(sEntry)
		if err != nil {
			return nil, fmt.Errorf("'%s' claim contains invalid entity identifier: %s", claim, err.Error())
		}
		parsed = append(parsed, *entityIdentifier)
	}
	return parsed, nil
}

func parseTrustMarkOwners(value any) (map[string]TrustMarkOwner, error) {
	owners, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'trust_mark_owners' claim must be a JSON object")
	}
	parsed := make(map[string]TrustMarkOwner, len(owners))
	for trustMarkType, owner := range owners {
		ownerObject, ok := owner.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q must be a JSON object", trustMarkType)
		}

		sub, present := ownerObject["sub"]
		if !present {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q is missing the required 'sub' member", trustMarkType)
		}
		sSub, ok := sub.(string)
		if !ok {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has a malformed 'sub' member", trustMarkType)
		}
		parsedSub, err := ValidateEntityIdentifier(sSub)
		if err != nil {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has a 'sub' member that is not a valid entity identifier: %s", trustMarkType, err.Error())
		}

		jwks, present := ownerObject["jwks"]
		if !present {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q is missing the required 'jwks' member", trustMarkType)
		}
		jwksObject, ok := jwks.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has a malformed 'jwks' member", trustMarkType)
		}
		if keys, present := jwksObject["keys"]; !present {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has a 'jwks' member with no 'keys' array", trustMarkType)
		} else if _, ok := keys.([]any); !ok {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has a 'jwks' member whose 'keys' is not an array", trustMarkType)
		}
		jwksBytes, err := json.Marshal(jwksObject)
		if err != nil {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has an unserialisable 'jwks' member", trustMarkType)
		}
		var parsedJwks josemodel.Jwks
		if err = json.Unmarshal(jwksBytes, &parsedJwks); err != nil {
			return nil, fmt.Errorf("'trust_mark_owners' entry for %q has an invalid 'jwks' member: %s", trustMarkType, err.Error())
		}

		additional := map[string]any{}
		for member, memberValue := range ownerObject {
			if member != "sub" && member != "jwks" {
				additional[member] = memberValue
			}
		}

		parsed[trustMarkType] = TrustMarkOwner{Sub: *parsedSub, JWKs: parsedJwks, AdditionalClaims: additional}
	}
	return parsed, nil
}

func parseNumericDate(claim string, value any) (int64, error) {
	f, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("'%s' claim is malformed", claim)
	}
	if f < 0 {
		return 0, fmt.Errorf("'%s' claim must not be negative", claim)
	}
	if f >= maxNumericDate {
		return 0, fmt.Errorf("'%s' claim is outside the representable range", claim)
	}
	return int64(f), nil
}

func parseCritClaim(claim string, value any, forbidden []string) ([]string, error) {
	entries, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("'%s' claim must be an array of strings", claim)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("'%s' claim must not be the empty array", claim)
	}
	parsed := make([]string, 0, len(entries))
	for _, entry := range entries {
		sEntry, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("'%s' claim must be an array of strings", claim)
		}
		if slices.Contains(forbidden, sEntry) {
			return nil, fmt.Errorf("'%s' claim must not list %q, which is defined by this specification", claim, sEntry)
		}
		if slices.Contains(parsed, sEntry) {
			return nil, fmt.Errorf("'%s' claim must not contain duplicate entries - %q appears more than once", claim, sEntry)
		}
		parsed = append(parsed, sEntry)
	}
	return parsed, nil
}

func (e *EntityStatement) UnmarshalJSON(data []byte) error {
	var jsonMap map[string]any
	err := json.Unmarshal(data, &jsonMap)
	if err != nil {
		return err
	}

	if iss, ok := jsonMap["iss"]; !ok {
		return fmt.Errorf("missing required body claim 'iss'")
	} else if sIss, ok := iss.(string); !ok {
		return fmt.Errorf("'iss' claim is malformed")
	} else if parsedIss, err := ValidateEntityIdentifier(sIss); err != nil {
		return fmt.Errorf("'iss' claim is not a valid entity identifier: %s", err.Error())
	} else {
		e.Iss = *parsedIss
	}

	if sub, ok := jsonMap["sub"]; !ok {
		return fmt.Errorf("missing required body claim 'sub'")
	} else if sSub, ok := sub.(string); !ok {
		return fmt.Errorf("'sub' claim is malformed")
	} else if parsedSub, err := ValidateEntityIdentifier(sSub); err != nil {
		return fmt.Errorf("'sub' claim is not a valid entity identifier: %s", err.Error())
	} else {
		e.Sub = *parsedSub
	}

	iatValue, ok := jsonMap["iat"]
	if !ok {
		return fmt.Errorf("missing required body claim 'iat'")
	}
	iat, err := parseNumericDate("iat", iatValue)
	if err != nil {
		return err
	}
	if iat > time.Now().Add(ClockSkewLeeway).UTC().Unix() {
		return fmt.Errorf("entity statement is issued in the future")
	}
	e.Iat = iat

	expValue, ok := jsonMap["exp"]
	if !ok {
		return fmt.Errorf("missing required body claim 'exp'")
	}
	exp, err := parseNumericDate("exp", expValue)
	if err != nil {
		return err
	}
	if time.Now().Add(-ClockSkewLeeway).UTC().Unix() > exp {
		return fmt.Errorf("entity statement has expired")
	}
	if iat >= exp {
		return fmt.Errorf("entity statement 'iat' claim must be before its 'exp' claim")
	}
	e.Exp = exp

	if authorityHints, ok := jsonMap["authority_hints"]; ok {
		parsed, err := parseEntityIdentifierArray("authority_hints", authorityHints)
		if err != nil {
			return err
		}
		e.AuthorityHints = parsed
	}

	if trustAnchorHints, ok := jsonMap["trust_anchor_hints"]; ok {
		parsed, err := parseEntityIdentifierArray("trust_anchor_hints", trustAnchorHints)
		if err != nil {
			return err
		}
		e.TrustAnchorHints = parsed
	}

	if jwks, ok := jsonMap["jwks"]; !ok {
		return fmt.Errorf("missing required body claim 'jwks'")
	} else {
		jwksObject, ok := jwks.(map[string]any)
		if !ok {
			return fmt.Errorf("malformed 'jwks' claim: must be a JSON object")
		}
		keys, present := jwksObject["keys"]
		if !present {
			return fmt.Errorf("malformed 'jwks' claim: missing required 'keys' member")
		}
		if _, ok := keys.([]any); !ok {
			return fmt.Errorf("malformed 'jwks' claim: 'keys' must be an array")
		}
		bytes, err := json.Marshal(jwks)
		if err != nil {
			return fmt.Errorf("malformed 'jwks' claim: invalid JSON")
		}
		if err = json.Unmarshal(bytes, &e.JWKs); err != nil {
			return fmt.Errorf("invalid 'jwks' claim: %s", err.Error())
		}
	}

	if entityMetadata, ok := jsonMap["metadata"]; ok {
		if entityMetadata == nil {
			return NewInvalidMetadataError("malformed 'metadata' claim: must not be null")
		}
		bytes, err := json.Marshal(entityMetadata)
		if err != nil {
			return NewInvalidMetadataError("malformed 'metadata' claim: invalid JSON")
		}
		var metadata Metadata
		if err = json.Unmarshal(bytes, &metadata); err != nil {
			return NewInvalidMetadataError(fmt.Sprintf("invalid 'metadata' claim: %s", err.Error()))
		}
		e.Metadata = &metadata
	}

	if metadataPolicy, ok := jsonMap["metadata_policy"]; ok {
		if metadataPolicy == nil {
			return NewInvalidMetadataError("malformed 'metadata_policy' claim: must not be null")
		}
		bytes, err := json.Marshal(metadataPolicy)
		if err != nil {
			return fmt.Errorf("malformed 'metadata_policy' claim: invalid JSON")
		}
		var metadataPolicy MetadataPolicy
		if err = json.Unmarshal(bytes, &metadataPolicy); err != nil {
			return fmt.Errorf("invalid 'metadata_policy' claim: %s", err.Error())
		}
		e.MetadataPolicy = &metadataPolicy
	}

	if entityTrustMarks, ok := jsonMap["trust_marks"]; ok {
		bytes, err := json.Marshal(entityTrustMarks)
		if err != nil {
			return fmt.Errorf("malformed 'trust_marks' claim: invalid JSON")
		}
		var trustMarks []TrustMarkHolder
		if err = json.Unmarshal(bytes, &trustMarks); err != nil {
			return fmt.Errorf("invalid 'trust_marks' claim: %s", err.Error())
		}
		e.TrustMarks = trustMarks
	}

	if trustMarkIssuers, ok := jsonMap["trust_mark_issuers"]; ok {
		if parsedTrustMarkIssuers, ok := trustMarkIssuers.(map[string]any); !ok {
			return fmt.Errorf("'trust_mark_issuers' claim is malformed")
		} else {
			parsedIssuers := make(map[string][]EntityIdentifier, len(parsedTrustMarkIssuers))
			for trustMarkType, issuers := range parsedTrustMarkIssuers {
				issuerList, ok := issuers.([]any)
				if !ok {
					return fmt.Errorf("'trust_mark_issuers' claim is malformed")
				}
				parsedEntities := make([]EntityIdentifier, 0, len(issuerList))
				for _, issuer := range issuerList {
					issuerString, ok := issuer.(string)
					if !ok {
						return fmt.Errorf("'trust_mark_issuers' claim contains malformed entity identifier")
					}
					entityIdentifier, err := ValidateEntityIdentifier(issuerString)
					if err != nil {
						return fmt.Errorf("'trust_mark_issuers' claim contains invalid entity identifier: %s", err.Error())
					}
					parsedEntities = append(parsedEntities, *entityIdentifier)
				}
				parsedIssuers[trustMarkType] = parsedEntities
			}
			e.TrustMarkIssuers = parsedIssuers
		}
	}

	if constraints, ok := jsonMap["constraints"]; ok {
		e.Constraints = constraints
	}

	if crit, ok := jsonMap["crit"]; ok {
		parsed, err := parseCritClaim("crit", crit, entityStatementClaims)
		if err != nil {
			return err
		}
		for _, name := range parsed {
			if _, present := jsonMap[name]; !present {
				return fmt.Errorf("'crit' claim lists %q, which is not present in the entity statement", name)
			}
		}
		return fmt.Errorf("'crit' claim lists %v, none of which this implementation understands", parsed)
	}

	if metadataPolicyCrit, ok := jsonMap["metadata_policy_crit"]; ok {
		parsed, err := parseCritClaim("metadata_policy_crit", metadataPolicyCrit, standardPolicyOperators)
		if err != nil {
			return err
		}
		return fmt.Errorf("'metadata_policy_crit' claim lists %v, none of which this implementation understands", parsed)
	}

	if trustMarkOwners, ok := jsonMap["trust_mark_owners"]; ok {
		parsed, err := parseTrustMarkOwners(trustMarkOwners)
		if err != nil {
			return err
		}
		e.TrustMarkOwners = parsed
	}

	if sourceEndpoint, ok := jsonMap["source_endpoint"]; ok {
		sEndpoint, ok := sourceEndpoint.(string)
		if !ok {
			return fmt.Errorf("'source_endpoint' claim must be a string")
		}
		if err := verifyHTTPSURLValue("source_endpoint", sEndpoint, true); err != nil {
			return err
		}
		if parsed, err := url.Parse(sEndpoint); err != nil || !parsed.IsAbs() || parsed.Host == "" {
			return fmt.Errorf("'source_endpoint' claim must be a valid absolute URL")
		}
		e.SourceEndpoint = &sEndpoint
	}

	return nil
}

type EntityTypeIdentifier interface {
	VerifyMetadata() error
}

type MetadataPolicyOperator interface {
	String() string
	Resolve(metadataParameterValue any) (any, error)
	ResolutionHierarchy() int
	Merge(valueToMerge any) (MetadataPolicyOperator, error)
	OperatorValue() any

	// ToSlice transforms the value of the MetadataPolicyOperator into a slice representation.
	// Used during certain metadata edge case handling
	ToSlice(key string) MetadataPolicyOperator
	CheckForConflict(containsFunc func(policyType reflect.Type) (MetadataPolicyOperator, bool)) error
}

type TrustMarkHolder struct {
	TrustMarkType string `json:"trust_mark_type"`
	TrustMark     string `json:"trust_mark"`
}

func (t *TrustMarkHolder) UnmarshalJSON(data []byte) error {
	var holder struct {
		TrustMarkType *string `json:"trust_mark_type"`
		TrustMark     *string `json:"trust_mark"`
	}
	if err := json.Unmarshal(data, &holder); err != nil {
		return err
	}
	if holder.TrustMarkType == nil || *holder.TrustMarkType == "" {
		return fmt.Errorf("each entry in 'trust_marks' requires a non-empty 'trust_mark_type' member")
	}
	if holder.TrustMark == nil || *holder.TrustMark == "" {
		return fmt.Errorf("each entry in 'trust_marks' requires a non-empty 'trust_mark' member")
	}

	parts := strings.SplitN(*holder.TrustMark, ".", 4)
	if len(parts) != 3 {
		return fmt.Errorf("the 'trust_mark' member of a 'trust_marks' entry must be a signed JWT")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("the 'trust_mark' member of a 'trust_marks' entry is not a decodable JWT: %s", err.Error())
	}
	var claims struct {
		TrustMarkType *string `json:"trust_mark_type"`
	}
	if err = json.Unmarshal(body, &claims); err != nil {
		return fmt.Errorf("the 'trust_mark' member of a 'trust_marks' entry has an unparseable body: %s", err.Error())
	}
	if claims.TrustMarkType == nil {
		return fmt.Errorf("the 'trust_mark' member of a 'trust_marks' entry has no 'trust_mark_type' claim")
	}
	if *claims.TrustMarkType != *holder.TrustMarkType {
		return fmt.Errorf("the 'trust_mark_type' member %q does not match the 'trust_mark_type' claim %q in the trust mark itself", *holder.TrustMarkType, *claims.TrustMarkType)
	}

	t.TrustMarkType = *holder.TrustMarkType
	t.TrustMark = *holder.TrustMark
	return nil
}

type Metadata struct {
	FederationMetadata                  *FederationMetadata                  `json:"federation_entity,omitempty"`
	OpenIDRelyingPartyMetadata          *OpenIDRelyingPartyMetadata          `json:"openid_relying_party,omitempty"`
	OpenIDConnectOpenIDProviderMetadata *OpenIDConnectOpenIDProviderMetadata `json:"openid_provider,omitempty"`
	OAuthAuthorizationServerMetadata    *OAuthAuthorizationServerMetadata    `json:"oauth_authorization_server,omitempty"`
	OAuthClientMetadata                 *OAuthClientMetadata                 `json:"oauth_client,omitempty"`
	OAuthResourceMetadata               *OAuthResourceMetadata               `json:"oauth_resource,omitempty"`
	OpenIDWalletProviderMetadata        *OpenIDWalletProviderMetadata        `json:"openid_wallet_provider,omitempty"`
	OpenIDCredentialIssuerMetadata      *OpenIDCredentialIssuerMetadata      `json:"openid_credential_issuer,omitempty"`
	OpenIDCredentialVerifierMetadata    *OpenIDCredentialVerifierMetadata    `json:"openid_credential_verifier,omitempty"`
	Extensions                          map[string]map[string]any            `json:"-"`
}

type MetadataPolicy struct {
	FederationMetadata                  map[string]PolicyOperators            `json:"federation_entity,omitempty"`
	OpenIDRelyingPartyMetadata          map[string]PolicyOperators            `json:"openid_relying_party,omitempty"`
	OpenIDConnectOpenIDProviderMetadata map[string]PolicyOperators            `json:"openid_provider,omitempty"`
	OAuthAuthorizationServerMetadata    map[string]PolicyOperators            `json:"oauth_authorization_server,omitempty"`
	OAuthClientMetadata                 map[string]PolicyOperators            `json:"oauth_client,omitempty"`
	OAuthResourceMetadata               map[string]PolicyOperators            `json:"oauth_resource,omitempty"`
	OpenIDWalletProviderMetadata        map[string]PolicyOperators            `json:"openid_wallet_provider,omitempty"`
	OpenIDCredentialIssuerMetadata      map[string]PolicyOperators            `json:"openid_credential_issuer,omitempty"`
	OpenIDCredentialVerifierMetadata    map[string]PolicyOperators            `json:"openid_credential_verifier,omitempty"`
	Extensions                          map[string]map[string]PolicyOperators `json:"-"`
}

var builtInEntityTypes = []string{
	"federation_entity",
	"openid_relying_party",
	"openid_provider",
	"oauth_authorization_server",
	"oauth_client",
	"oauth_resource",
	"openid_wallet_provider",
	"openid_credential_issuer",
	"openid_credential_verifier",
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	var bytesMap map[string]any
	err := json.Unmarshal(data, &bytesMap)
	if err != nil {
		return err
	}

	for entityType, entityMetadata := range bytesMap {
		parameters, ok := entityMetadata.(map[string]any)
		if !ok {
			return fmt.Errorf("the value of entity type %q must be a JSON object", entityType)
		}
		for parameter, value := range parameters {
			if value == nil {
				return fmt.Errorf("metadata parameter %q of entity type %q must not be null", parameter, entityType)
			}
		}
	}

	if federation, ok := bytesMap["federation_entity"]; ok {
		m.FederationMetadata, err = ReMarshalJsonAsEntityMetadata[FederationMetadata](federation)
		if err != nil {
			return fmt.Errorf("malformed federation entity metadata: %s", err.Error())
		}
		if m.FederationMetadata != nil {
			err = m.FederationMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid federation entity metadata: %w", err)
			}
		}
	}
	if openidRelyingParty, ok := bytesMap["openid_relying_party"]; ok {
		m.OpenIDRelyingPartyMetadata, err = ReMarshalJsonAsEntityMetadata[OpenIDRelyingPartyMetadata](openidRelyingParty)
		if err != nil {
			return fmt.Errorf("malformed openid relying party metadata: %s", err.Error())
		}
		if m.OpenIDRelyingPartyMetadata != nil {
			err = m.OpenIDRelyingPartyMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid openid relying party metadata: %w", err)
			}
		}
	}
	if openidProvider, ok := bytesMap["openid_provider"]; ok {
		m.OpenIDConnectOpenIDProviderMetadata, err = ReMarshalJsonAsEntityMetadata[OpenIDConnectOpenIDProviderMetadata](openidProvider)
		if err != nil {
			return fmt.Errorf("malformed openid provider metadata: %s", err.Error())
		}
		if m.OpenIDConnectOpenIDProviderMetadata != nil {
			err = m.OpenIDConnectOpenIDProviderMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid openid connect openid provider metadata: %w", err)
			}
		}
	}
	if oauthAuthorizationServer, ok := bytesMap["oauth_authorization_server"]; ok {
		m.OAuthAuthorizationServerMetadata, err = ReMarshalJsonAsEntityMetadata[OAuthAuthorizationServerMetadata](oauthAuthorizationServer)
		if err != nil {
			return fmt.Errorf("malformed oauth authorization server metadata: %s", err.Error())
		}
		if m.OAuthAuthorizationServerMetadata != nil {
			err = m.OAuthAuthorizationServerMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid oauth authorization server metadata: %w", err)
			}
		}
	}
	if oauthClient, ok := bytesMap["oauth_client"]; ok {
		m.OAuthClientMetadata, err = ReMarshalJsonAsEntityMetadata[OAuthClientMetadata](oauthClient)
		if err != nil {
			return fmt.Errorf("malformed oauth client metadata: %s", err.Error())
		}
		if m.OAuthClientMetadata != nil {
			err = m.OAuthClientMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid oauth client metadata: %w", err)
			}
		}
	}
	if oauthResource, ok := bytesMap["oauth_resource"]; ok {
		m.OAuthResourceMetadata, err = ReMarshalJsonAsEntityMetadata[OAuthResourceMetadata](oauthResource)
		if err != nil {
			return fmt.Errorf("malformed oauth resource metadata: %s", err.Error())
		}
		if m.OAuthResourceMetadata != nil {
			err = m.OAuthResourceMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid oauth resource metadata: %w", err)
			}
		}
	}
	if openidWalletProvider, ok := bytesMap["openid_wallet_provider"]; ok {
		m.OpenIDWalletProviderMetadata, err = ReMarshalJsonAsEntityMetadata[OpenIDWalletProviderMetadata](openidWalletProvider)
		if err != nil {
			return fmt.Errorf("malformed openid wallet provider metadata: %s", err.Error())
		}
		if m.OpenIDWalletProviderMetadata != nil {
			err = m.OpenIDWalletProviderMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid openid wallet provider metadata: %w", err)
			}
		}
	}
	if openidCredentialIssuer, ok := bytesMap["openid_credential_issuer"]; ok {
		m.OpenIDCredentialIssuerMetadata, err = ReMarshalJsonAsEntityMetadata[OpenIDCredentialIssuerMetadata](openidCredentialIssuer)
		if err != nil {
			return fmt.Errorf("malformed openid credential issuer metadata: %s", err.Error())
		}
		if m.OpenIDCredentialIssuerMetadata != nil {
			err = m.OpenIDCredentialIssuerMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid openid credential issuer metadata: %w", err)
			}
		}
	}
	if openidCredentialVerifier, ok := bytesMap["openid_credential_verifier"]; ok {
		m.OpenIDCredentialVerifierMetadata, err = ReMarshalJsonAsEntityMetadata[OpenIDCredentialVerifierMetadata](openidCredentialVerifier)
		if err != nil {
			return fmt.Errorf("malformed openid credential verifier metadata: %s", err.Error())
		}
		if m.OpenIDCredentialVerifierMetadata != nil {
			err = m.OpenIDCredentialVerifierMetadata.VerifyMetadata()
			if err != nil {
				return fmt.Errorf("invalid openid credential verifier metadata: %w", err)
			}
		}
	}
	for entityType, entityMetadata := range bytesMap {
		if slices.Contains(builtInEntityTypes, entityType) {
			continue
		}
		parsed, err := ReMarshalJsonAsEntityMetadata[map[string]any](entityMetadata)
		if err != nil {
			return fmt.Errorf("malformed %s metadata: %s", entityType, err.Error())
		}
		if m.Extensions == nil {
			m.Extensions = map[string]map[string]any{}
		}
		m.Extensions[entityType] = *parsed
	}
	return nil
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	resultMap := map[string]any{}
	if m.FederationMetadata != nil {
		resultMap["federation_entity"] = marshalMetadataToMap(*m.FederationMetadata)
	}
	if m.OpenIDRelyingPartyMetadata != nil {
		resultMap["openid_relying_party"] = marshalMetadataToMap(*m.OpenIDRelyingPartyMetadata)
	}
	if m.OpenIDConnectOpenIDProviderMetadata != nil {
		resultMap["openid_provider"] = marshalMetadataToMap(*m.OpenIDConnectOpenIDProviderMetadata)
	}
	if m.OAuthAuthorizationServerMetadata != nil {
		resultMap["oauth_authorization_server"] = marshalMetadataToMap(*m.OAuthAuthorizationServerMetadata)
	}
	if m.OAuthClientMetadata != nil {
		resultMap["oauth_client"] = marshalMetadataToMap(*m.OAuthClientMetadata)
	}
	if m.OAuthResourceMetadata != nil {
		resultMap["oauth_resource"] = marshalMetadataToMap(*m.OAuthResourceMetadata)
	}
	if m.OpenIDWalletProviderMetadata != nil {
		resultMap["openid_wallet_provider"] = marshalMetadataToMap(*m.OpenIDWalletProviderMetadata)
	}
	if m.OpenIDCredentialIssuerMetadata != nil {
		resultMap["openid_credential_issuer"] = marshalMetadataToMap(*m.OpenIDCredentialIssuerMetadata)
	}
	if m.OpenIDCredentialVerifierMetadata != nil {
		resultMap["openid_credential_verifier"] = marshalMetadataToMap(*m.OpenIDCredentialVerifierMetadata)
	}
	for entityType, entityMetadata := range m.Extensions {
		resultMap[entityType] = marshalMetadataToMap(entityMetadata)
	}
	return json.Marshal(resultMap)
}

func (m *MetadataPolicy) UnmarshalJSON(data []byte) error {
	var bytesMap map[string]any
	err := json.Unmarshal(data, &bytesMap)
	if err != nil {
		return err
	}
	if federation, ok := bytesMap["federation_entity"]; ok {
		federationPolicyOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](federation)
		if err != nil {
			return fmt.Errorf("malformed federation entity metadata policy: %s", err.Error())
		}
		m.FederationMetadata = *federationPolicyOperators
	}
	if openidRelyingParty, ok := bytesMap["openid_relying_party"]; ok {
		openidRelyingPartyOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](openidRelyingParty)
		if err != nil {
			return fmt.Errorf("malformed openid relying party metadata policy: %s", err.Error())
		}
		m.OpenIDRelyingPartyMetadata = *openidRelyingPartyOperators
	}
	if openidProvider, ok := bytesMap["openid_provider"]; ok {
		openidProviderOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](openidProvider)
		if err != nil {
			return fmt.Errorf("malformed openid provider metadata policy: %s", err.Error())
		}
		m.OpenIDConnectOpenIDProviderMetadata = *openidProviderOperators
	}
	if oauthAuthorizationServer, ok := bytesMap["oauth_authorization_server"]; ok {
		oauthAuthorizationServerOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](oauthAuthorizationServer)
		if err != nil {
			return fmt.Errorf("malformed oauth authorization server metadata policy: %s", err.Error())
		}
		m.OAuthAuthorizationServerMetadata = *oauthAuthorizationServerOperators
	}
	if oauthClient, ok := bytesMap["oauth_client"]; ok {
		oauthClientOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](oauthClient)
		if err != nil {
			return fmt.Errorf("malformed oauth client metadata policy: %s", err.Error())
		}
		m.OAuthClientMetadata = *oauthClientOperators
	}
	if oauthResource, ok := bytesMap["oauth_resource"]; ok {
		oauthResourceOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](oauthResource)
		if err != nil {
			return fmt.Errorf("malformed oauth resource metadata policy: %s", err.Error())
		}
		m.OAuthResourceMetadata = *oauthResourceOperators
	}
	if openidWalletProvider, ok := bytesMap["openid_wallet_provider"]; ok {
		openidWalletProviderOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](openidWalletProvider)
		if err != nil {
			return fmt.Errorf("malformed openid wallet provider metadata policy: %s", err.Error())
		}
		m.OpenIDWalletProviderMetadata = *openidWalletProviderOperators
	}
	if openidCredentialIssuer, ok := bytesMap["openid_credential_issuer"]; ok {
		openidCredentialIssuerOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](openidCredentialIssuer)
		if err != nil {
			return fmt.Errorf("malformed openid credential issuer metadata policy: %s", err.Error())
		}
		m.OpenIDCredentialIssuerMetadata = *openidCredentialIssuerOperators
	}
	if openidCredentialVerifier, ok := bytesMap["openid_credential_verifier"]; ok {
		openidCredentialVerifierOperators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](openidCredentialVerifier)
		if err != nil {
			return fmt.Errorf("malformed openid credential verifier metadata policy: %s", err.Error())
		}
		m.OpenIDCredentialVerifierMetadata = *openidCredentialVerifierOperators
	}
	for entityType, entityPolicy := range bytesMap {
		if slices.Contains(builtInEntityTypes, entityType) {
			continue
		}
		operators, err := ReMarshalJsonAsEntityMetadata[map[string]PolicyOperators](entityPolicy)
		if err != nil {
			return fmt.Errorf("malformed %s metadata policy: %s", entityType, err.Error())
		}
		if m.Extensions == nil {
			m.Extensions = map[string]map[string]PolicyOperators{}
		}
		m.Extensions[entityType] = *operators
	}
	return nil
}

func (m MetadataPolicy) MarshalJSON() ([]byte, error) {
	resultMap := map[string]any{}
	if m.FederationMetadata != nil {
		resultMap["federation_entity"] = marshalPolicyOperatorSetToMap(m.FederationMetadata)
	}
	if m.OpenIDRelyingPartyMetadata != nil {
		resultMap["openid_relying_party"] = marshalPolicyOperatorSetToMap(m.OpenIDRelyingPartyMetadata)
	}
	if m.OpenIDConnectOpenIDProviderMetadata != nil {
		resultMap["openid_provider"] = marshalPolicyOperatorSetToMap(m.OpenIDConnectOpenIDProviderMetadata)
	}
	if m.OAuthAuthorizationServerMetadata != nil {
		resultMap["oauth_authorization_server"] = marshalPolicyOperatorSetToMap(m.OAuthAuthorizationServerMetadata)
	}
	if m.OAuthClientMetadata != nil {
		resultMap["oauth_client"] = marshalPolicyOperatorSetToMap(m.OAuthClientMetadata)
	}
	if m.OAuthResourceMetadata != nil {
		resultMap["oauth_resource"] = marshalPolicyOperatorSetToMap(m.OAuthResourceMetadata)
	}
	if m.OpenIDWalletProviderMetadata != nil {
		resultMap["openid_wallet_provider"] = marshalPolicyOperatorSetToMap(m.OpenIDWalletProviderMetadata)
	}
	if m.OpenIDCredentialIssuerMetadata != nil {
		resultMap["openid_credential_issuer"] = marshalPolicyOperatorSetToMap(m.OpenIDCredentialIssuerMetadata)
	}
	if m.OpenIDCredentialVerifierMetadata != nil {
		resultMap["openid_credential_verifier"] = marshalPolicyOperatorSetToMap(m.OpenIDCredentialVerifierMetadata)
	}
	for entityType, operators := range m.Extensions {
		resultMap[entityType] = marshalPolicyOperatorSetToMap(operators)
	}
	return json.Marshal(resultMap)
}

func (m *Metadata) byEntityType() map[string]map[string]any {
	entries := map[string]map[string]any{}
	if m.FederationMetadata != nil {
		entries["federation_entity"] = *m.FederationMetadata
	}
	if m.OpenIDRelyingPartyMetadata != nil {
		entries["openid_relying_party"] = *m.OpenIDRelyingPartyMetadata
	}
	if m.OpenIDConnectOpenIDProviderMetadata != nil {
		entries["openid_provider"] = *m.OpenIDConnectOpenIDProviderMetadata
	}
	if m.OAuthAuthorizationServerMetadata != nil {
		entries["oauth_authorization_server"] = *m.OAuthAuthorizationServerMetadata
	}
	if m.OAuthClientMetadata != nil {
		entries["oauth_client"] = *m.OAuthClientMetadata
	}
	if m.OAuthResourceMetadata != nil {
		entries["oauth_resource"] = *m.OAuthResourceMetadata
	}
	if m.OpenIDWalletProviderMetadata != nil {
		entries["openid_wallet_provider"] = *m.OpenIDWalletProviderMetadata
	}
	if m.OpenIDCredentialIssuerMetadata != nil {
		entries["openid_credential_issuer"] = *m.OpenIDCredentialIssuerMetadata
	}
	if m.OpenIDCredentialVerifierMetadata != nil {
		entries["openid_credential_verifier"] = *m.OpenIDCredentialVerifierMetadata
	}
	for entityType, entityMetadata := range m.Extensions {
		entries[entityType] = entityMetadata
	}
	return entries
}

func (m *MetadataPolicy) byEntityType() map[string]map[string]PolicyOperators {
	entries := map[string]map[string]PolicyOperators{
		"federation_entity":          m.FederationMetadata,
		"openid_relying_party":       m.OpenIDRelyingPartyMetadata,
		"openid_provider":            m.OpenIDConnectOpenIDProviderMetadata,
		"oauth_authorization_server": m.OAuthAuthorizationServerMetadata,
		"oauth_client":               m.OAuthClientMetadata,
		"oauth_resource":             m.OAuthResourceMetadata,
		"openid_wallet_provider":     m.OpenIDWalletProviderMetadata,
		"openid_credential_issuer":   m.OpenIDCredentialIssuerMetadata,
		"openid_credential_verifier": m.OpenIDCredentialVerifierMetadata,
	}
	for entityType, operators := range m.Extensions {
		entries[entityType] = operators
	}
	return entries
}

func (m *MetadataPolicy) HasParameterPolicies() bool {
	for _, parameters := range m.byEntityType() {
		for _, operators := range parameters {
			if len(operators.Metadata) > 0 {
				return true
			}
		}
	}
	return false
}

func (m *MetadataPolicy) setEntityType(entityType string, operators map[string]PolicyOperators) {
	switch entityType {
	case "federation_entity":
		m.FederationMetadata = operators
	case "openid_relying_party":
		m.OpenIDRelyingPartyMetadata = operators
	case "openid_provider":
		m.OpenIDConnectOpenIDProviderMetadata = operators
	case "oauth_authorization_server":
		m.OAuthAuthorizationServerMetadata = operators
	case "oauth_client":
		m.OAuthClientMetadata = operators
	case "oauth_resource":
		m.OAuthResourceMetadata = operators
	case "openid_wallet_provider":
		m.OpenIDWalletProviderMetadata = operators
	case "openid_credential_issuer":
		m.OpenIDCredentialIssuerMetadata = operators
	case "openid_credential_verifier":
		m.OpenIDCredentialVerifierMetadata = operators
	default:
		if m.Extensions == nil {
			m.Extensions = map[string]map[string]PolicyOperators{}
		}
		m.Extensions[entityType] = operators
	}
}

func (m *Metadata) FilterByEntityTypes(entityTypes []string) {
	if len(entityTypes) == 0 {
		return
	}
	if !slices.Contains(entityTypes, "federation_entity") {
		m.FederationMetadata = nil
	}
	if !slices.Contains(entityTypes, "openid_relying_party") {
		m.OpenIDRelyingPartyMetadata = nil
	}
	if !slices.Contains(entityTypes, "openid_provider") {
		m.OpenIDConnectOpenIDProviderMetadata = nil
	}
	if !slices.Contains(entityTypes, "oauth_authorization_server") {
		m.OAuthAuthorizationServerMetadata = nil
	}
	if !slices.Contains(entityTypes, "oauth_client") {
		m.OAuthClientMetadata = nil
	}
	if !slices.Contains(entityTypes, "oauth_resource") {
		m.OAuthResourceMetadata = nil
	}
	if !slices.Contains(entityTypes, "openid_wallet_provider") {
		m.OpenIDWalletProviderMetadata = nil
	}
	if !slices.Contains(entityTypes, "openid_credential_issuer") {
		m.OpenIDCredentialIssuerMetadata = nil
	}
	if !slices.Contains(entityTypes, "openid_credential_verifier") {
		m.OpenIDCredentialVerifierMetadata = nil
	}
	for entityType := range m.Extensions {
		if !slices.Contains(entityTypes, entityType) {
			delete(m.Extensions, entityType)
		}
	}
}

func marshalPolicyOperatorSetToMap(in map[string]PolicyOperators) map[string]any {
	metadataMap := map[string]any{}
	for k, v := range in {
		operatorMap := map[string]any{}
		for _, operator := range v.Metadata {
			operatorMap[operator.String()] = operator.OperatorValue()
		}
		metadataMap[k] = operatorMap
	}
	return metadataMap
}

func marshalMetadataToMap(in map[string]any) map[string]any {
	metadataMap := map[string]any{}
	for k, v := range in {
		if _, ok := v.([]any); !ok && v == nil {
			continue // non-slice nil values can be completely omitted
		} else if nested, ok := v.(map[string]any); ok {
			metadataMap[k] = marshalMetadataToMap(nested)
		} else if reflect.TypeOf(v).Kind() == reflect.Map {
			nestedValue := reflect.ValueOf(v)
			converted := make(map[string]any, nestedValue.Len())
			for _, key := range nestedValue.MapKeys() {
				converted[fmt.Sprintf("%v", key.Interface())] = nestedValue.MapIndex(key).Interface()
			}
			metadataMap[k] = marshalMetadataToMap(converted)
		} else if reflect.TypeOf(v).Kind() == reflect.Slice {
			if reflect.ValueOf(v).Len() == 0 {
				metadataMap[k] = []any{}
			} else {
				// Convert any slice to []any
				slice := reflect.ValueOf(v)
				anySlice := make([]any, slice.Len())
				for i := 0; i < slice.Len(); i++ {
					anySlice[i] = slice.Index(i).Interface()
				}
				metadataMap[k] = anySlice
			}
		} else {
			metadataMap[k] = v
		}
	}
	return metadataMap
}

type ResolveResponse struct {
	Iss        EntityIdentifier  `json:"iss"`
	Sub        EntityIdentifier  `json:"sub"`
	Iat        int64             `json:"iat"`
	Exp        int64             `json:"exp"`
	Metadata   *Metadata         `json:"metadata,omitempty"`
	TrustMarks []TrustMarkHolder `json:"trust_marks,omitempty"`
	TrustChain []string          `json:"trust_chain,omitempty"`
}

type TrustMarkStatusResponse struct {
	Status string `json:"status"`
}

func Pointer[T any](v T) *T {
	return &v
}

type TrustMark struct {
	Issuer           string         `json:"iss"`
	Sub              string         `json:"sub"`
	Type             string         `json:"trust_mark_type"`
	IssuedAt         int64          `json:"iat"`
	LogoURI          *string        `json:"logo_uri,omitempty"`
	Expiry           *int64         `json:"exp,omitempty"`
	Ref              *string        `json:"ref,omitempty"`
	DelegationJWT    *string        `json:"delegation,omitempty"`
	AdditionalClaims map[string]any `json:"-"`
}

func (t *TrustMark) UnmarshalJSON(data []byte) error {
	var jsonMap map[string]any
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return err
	}

	if iss, ok := jsonMap["iss"].(string); !ok {
		return fmt.Errorf("missing or invalid required field 'iss'")
	} else {
		t.Issuer = iss
	}

	if sub, ok := jsonMap["sub"].(string); !ok {
		return fmt.Errorf("missing or invalid required field 'sub'")
	} else {
		t.Sub = sub
	}

	if trustMarkType, ok := jsonMap["trust_mark_type"].(string); !ok {
		return fmt.Errorf("missing or invalid required field 'trust_mark_type'")
	} else {
		t.Type = trustMarkType
	}

	if iat, ok := jsonMap["iat"].(float64); !ok {
		return fmt.Errorf("missing or invalid required field 'iat'")
	} else {
		t.IssuedAt = int64(iat)
	}

	if logoURI, ok := jsonMap["logo_uri"].(string); ok {
		t.LogoURI = &logoURI
	}

	if exp, ok := jsonMap["exp"].(float64); ok {
		expInt := int64(exp)
		t.Expiry = &expInt
	}

	if ref, ok := jsonMap["ref"].(string); ok {
		t.Ref = &ref
	}

	if delegation, ok := jsonMap["delegation"].(string); ok {
		t.DelegationJWT = &delegation
	}

	t.AdditionalClaims = make(map[string]any)
	knownFields := []string{"iss", "sub", "trust_mark_type", "iat", "logo_uri", "exp", "ref", "delegation"}

	for key, value := range jsonMap {
		if !slices.Contains(knownFields, key) {
			t.AdditionalClaims[key] = value
		}
	}

	return nil
}
