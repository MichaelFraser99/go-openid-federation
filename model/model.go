package model

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	josemodel "github.com/MichaelFraser99/go-jose/model"
)

type ServerConfiguration struct {
	SignerConfiguration         SignerConfiguration
	EntityIdentifier            EntityIdentifier
	AuthorityHints              []EntityIdentifier
	TrustMarks                  []TrustMarkHolder
	EntityConfiguration         EntityStatement
	EntityConfigurationLifetime time.Duration
	IntermediateConfiguration   *IntermediateConfiguration
	HttpClient                  *http.Client
	Extensions                  Extensions
	MetadataRetriever           Retriever
	TrustMarkIssuerRetriever    TrustMarkIssuerRetriever
	TrustMarkRetriever          TrustMarkRetriever
}

func (s *ServerConfiguration) GetSubordinates() (map[EntityIdentifier]*SubordinateConfiguration, error) {
	if s.MetadataRetriever != nil {
		return s.MetadataRetriever.GetSubordinates()
	}
	return s.IntermediateConfiguration.subordinates, nil
}

func (s *ServerConfiguration) GetSubordinateJWKs() ([]SignerConfiguration, error) {
	if s.MetadataRetriever != nil {
		return s.MetadataRetriever.GetSubordinateSigners()
	}

	var signers []SignerConfiguration

	subordinates, err := s.GetSubordinates()
	if err != nil {
		return nil, err
	}
	for _, subordinateConfiguration := range subordinates {
		if subordinateConfiguration.SignerConfiguration != nil {
			signers = append(signers, *subordinateConfiguration.SignerConfiguration)
		}
	}
	return signers, nil
}

func (s *ServerConfiguration) GetSubordinate(identifier EntityIdentifier) (*SubordinateConfiguration, error) {
	if s.IntermediateConfiguration.subordinates == nil {
		s.IntermediateConfiguration.subordinates = map[EntityIdentifier]*SubordinateConfiguration{}
	}

	if s.IntermediateConfiguration.subordinates[identifier] != nil && time.Now().UTC().Before(time.Unix(s.IntermediateConfiguration.subordinates[identifier].CachedAt, 0).Add(s.IntermediateConfiguration.SubordinateCacheTime).UTC()) {
		return s.IntermediateConfiguration.subordinates[identifier], nil
	} else if s.MetadataRetriever != nil {
		entity, err := s.MetadataRetriever.GetSubordinate(identifier)
		if err != nil {
			return nil, err
		} else {
			s.IntermediateConfiguration.subordinates[identifier] = entity
			s.IntermediateConfiguration.subordinates[identifier].CachedAt = time.Now().UTC().Unix()
		}
		return s.IntermediateConfiguration.subordinates[identifier], nil
	} else {
		return nil, fmt.Errorf("subordinate entity %s not found", identifier)
	}
}

type Retriever interface {
	GetSubordinate(identifier EntityIdentifier) (*SubordinateConfiguration, error)
	GetSubordinates() (map[EntityIdentifier]*SubordinateConfiguration, error)
	GetSubordinateSigners() ([]SignerConfiguration, error)
}

type TrustMarkIssuerRetriever interface {
	ListTrustMarkIssuers() (map[string][]EntityIdentifier, error)
}

type TrustMarkRetriever interface {
	GetTrustMarkStatus(trustMark string) (*string, error)
	IssueTrustMark(trustMarkIdentifier string, entityIdentifier EntityIdentifier) (*string, error)
	ListTrustMarks(trustMarkIdentifier string, identifier *EntityIdentifier) ([]EntityIdentifier, error)
}

type ExtendedListingRetriever interface {
	GetExtendedSubordinates(from *EntityIdentifier, size int, claims []string) (*ExtendedListingResponse, error)
}

type SubordinateStatusRetriever interface {
	GetSubordinateStatus(sub *EntityIdentifier) (*SubordinateStatusResponse, error)
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
	subordinates                 map[EntityIdentifier]*SubordinateConfiguration
	SubordinateStatementLifetime time.Duration
	SubordinateCacheTime         time.Duration
}

func (i *IntermediateConfiguration) AddSubordinate(identifier EntityIdentifier, subordinateConfiguration *SubordinateConfiguration) {
	if i.subordinates == nil {
		i.subordinates = map[EntityIdentifier]*SubordinateConfiguration{}
	}
	subordinateConfiguration.JWKs.Opts.EnforceUniqueKIDs = true
	subordinateConfiguration.CachedAt = time.Now().UTC().Unix()

	i.subordinates[identifier] = subordinateConfiguration
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

type ExtendedListingResponse struct {
	ImmediateSubordinateEntities []map[string]any  `json:"immediate_subordinate_entities"`
	NextEntityID                 *EntityIdentifier `json:"next_entity_id,omitempty"`
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
	Iss                EntityIdentifier              `json:"iss"`
	Sub                EntityIdentifier              `json:"sub"`
	Iat                int64                         `json:"iat"`
	Exp                int64                         `json:"exp"`
	JWKs               josemodel.Jwks                `json:"jwks"`
	AuthorityHints     []EntityIdentifier            `json:"authority_hints,omitempty"`
	Metadata           *Metadata                     `json:"metadata,omitempty"`
	MetadataPolicy     *MetadataPolicy               `json:"metadata_policy,omitempty"`
	Constraints        any                           `json:"constraints,omitempty"`          //todo
	Crit               any                           `json:"crit,omitempty"`                 //todo - also note - empty array is banned
	MetadataPolicyCrit any                           `json:"metadata_policy_crit,omitempty"` //todo - also note - empty array is banned
	TrustMarks         []TrustMarkHolder             `json:"trust_marks,omitempty"`
	TrustMarkIssuers   map[string][]EntityIdentifier `json:"trust_mark_issuers,omitempty"`
	TrustMarkOwners    any                           `json:"trust_mark_owners,omitempty"` //todo
	SourceEndpoint     any                           `json:"source_endpoint,omitempty"`   //todo
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
	} else {
		e.Iss = EntityIdentifier(sIss)
	}

	if sub, ok := jsonMap["sub"]; !ok {
		return fmt.Errorf("missing required body claim 'sub'")
	} else if sSub, ok := sub.(string); !ok {
		return fmt.Errorf("'sub' claim is malformed")
	} else {
		e.Sub = EntityIdentifier(sSub)
	}

	if _, ok := jsonMap["iat"]; !ok {
		return fmt.Errorf("missing required body claim 'iat'")
	} else if fIat, ok := jsonMap["iat"].(float64); !ok {
		return fmt.Errorf("'iat' claim is malformed")
	} else {
		e.Iat = int64(fIat)
	}

	if exp, ok := jsonMap["exp"]; !ok {
		return fmt.Errorf("missing required body claim 'exp'")
	} else if iExp, ok := exp.(float64); !ok {
		return fmt.Errorf("'exp' claim is malformed")
	} else {
		if time.Now().UTC().Unix() > int64(iExp) {
			return fmt.Errorf("entity statement has expired")
		}
		e.Exp = int64(iExp)
	}

	if authorityHints, ok := jsonMap["authority_hints"]; ok {
		if sAuthorityHints, ok := authorityHints.([]any); !ok {
			return fmt.Errorf("'authority_hints' claim is malformed")
		} else {
			parsedAuthorityHints := make([]EntityIdentifier, 0)
			for _, hint := range sAuthorityHints {
				if sHint, ok := hint.(string); !ok {
					return fmt.Errorf("'authority_hints' claim contains malformed entity identifier")
				} else if entityIdentifier, err := ValidateEntityIdentifier(sHint); err != nil {
					return fmt.Errorf("'authority_hints' claim contains invalid entity identifier: %s", err.Error())
				} else {
					parsedAuthorityHints = append(parsedAuthorityHints, *entityIdentifier)
				}
			}
			e.AuthorityHints = parsedAuthorityHints
		}

	}

	if jwks, ok := jsonMap["jwks"]; !ok {
		return fmt.Errorf("missing required body claim 'jwks'")
	} else {
		bytes, err := json.Marshal(jwks)
		if err != nil {
			return fmt.Errorf("malformed 'jwks' claim: invalid JSON")
		}
		err = json.Unmarshal(bytes, &e.JWKs)
		if err != nil {
			return fmt.Errorf("invalid 'jwks' claim: %s", err.Error())
		}
	}

	if entityMetadata, ok := jsonMap["metadata"]; ok {
		bytes, err := json.Marshal(entityMetadata)
		if err != nil {
			return fmt.Errorf("malformed 'metadata' claim: invalid JSON")
		}
		var metadata Metadata
		err = json.Unmarshal(bytes, &metadata)
		if err != nil {
			return fmt.Errorf("invalid 'metadata' claim: %s", err.Error())
		}
		e.Metadata = &metadata
	}

	if metadataPolicy, ok := jsonMap["metadata_policy"]; ok {
		bytes, err := json.Marshal(metadataPolicy)
		if err != nil {
			return fmt.Errorf("malformed 'metadata_policy' claim: invalid JSON")
		}
		var metadataPolicy MetadataPolicy
		err = json.Unmarshal(bytes, &metadataPolicy)
		if err != nil {
			return fmt.Errorf("invalid 'metadata_policy' claim: %s", err.Error())
		}
		e.MetadataPolicy = &metadataPolicy
	}
	return nil
}

type EntityTypeIdentifier interface {
	VerifyMetadata() error
}

//todo: oauth_authorization_server, oauth_client, oauth_resource

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

type Metadata struct {
	FederationMetadata                  *FederationMetadata                  `json:"federation_entity,omitempty"`
	OpenIDRelyingPartyMetadata          *OpenIDRelyingPartyMetadata          `json:"openid_relying_party,omitempty"`
	OpenIDConnectOpenIDProviderMetadata *OpenIDConnectOpenIDProviderMetadata `json:"openid_provider,omitempty"`
}

type MetadataPolicy struct {
	FederationMetadata                  map[string]PolicyOperators `json:"federation_entity,omitempty"`
	OpenIDRelyingPartyMetadata          map[string]PolicyOperators `json:"openid_relying_party,omitempty"`
	OpenIDConnectOpenIDProviderMetadata map[string]PolicyOperators `json:"openid_provider,omitempty"`
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	var bytesMap map[string]any
	err := json.Unmarshal(data, &bytesMap)
	if err != nil {
		return err
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
	return json.Marshal(resultMap)
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
		} else if reflect.TypeOf(v).Kind() == reflect.Map {
			metadataMap[k] = marshalMetadataToMap(v.(map[string]any))
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
	Iss        EntityIdentifier `json:"iss"`
	Sub        EntityIdentifier `json:"sub"`
	Iat        int64            `json:"iat"`
	Exp        int64            `json:"exp"`
	Metadata   *Metadata        `json:"metadata,omitempty"`
	TrustMarks any              `json:"trust_marks,omitempty"` //todo
	TrustChain []string         `json:"trust_chain,omitempty"`
}

type TrustMarkStatusResponse struct {
	Status string `json:"status"`
}

func Pointer[T any](v T) *T {
	return &v
}
