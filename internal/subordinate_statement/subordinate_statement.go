package subordinate_statement

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Retrieve(ctx context.Context, cfg model.Configuration, issuer model.EntityStatement, subject model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	if cfg.HttpClient == nil {
		return nil, nil, fmt.Errorf("no http client present")
	}
	if issuer.Iss != issuer.Sub {
		return nil, nil, fmt.Errorf("the value of 'issuer' must be an entity configuration")
	}
	if issuer.Metadata == nil || issuer.Metadata.FederationMetadata == nil || (*issuer.Metadata.FederationMetadata)["federation_fetch_endpoint"] == nil {
		return nil, nil, fmt.Errorf("issuer entity statement does not list a federation fetch endpoint within it's federation metadata")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%ssub=%s", func() string {
		trimmedString := strings.TrimSuffix((*issuer.Metadata.FederationMetadata)["federation_fetch_endpoint"].(string), "/")
		if strings.Contains(trimmedString, "?") {
			return trimmedString + "&"
		} else {
			return trimmedString + "?"
		}
	}(), url.QueryEscape(string(subject))), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/entity-statement+jwt")

	response, err := cfg.HttpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("non-200 response from %q's federation fetch endpoint: %s", issuer.Sub, response.Status)
	}

	if !strings.Contains(response.Header.Get("Content-Type"), "application/entity-statement+jwt") { //todo: check on this - not sure if it has to be an exact match or not...
		return nil, nil, fmt.Errorf("invalid Content-Type response from %q's federation fetch response: %s", issuer.Sub, response.Header.Get("Content-Type"))
	}

	limit := cfg.PeerResponseLimit()
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %q's federation fetch response body: %s", issuer.Sub, err.Error())
	}
	if int64(len(responseBytes)) > limit {
		return nil, nil, fmt.Errorf("%q's federation fetch response exceeded the %d byte response limit", issuer.Sub, limit)
	}

	subordinateStatement, err := Validate(cfg, issuer, string(responseBytes))
	if err != nil {
		return nil, nil, err
	}

	if subordinateStatement.Sub != subject {
		return nil, nil, fmt.Errorf("'sub' claim does not match the requested subject entity identifier")
	}

	return josemodel.Pointer(string(responseBytes)), subordinateStatement, nil
}

func Validate(cfg model.Configuration, issuer model.EntityStatement, subordinateStatementJwt string) (*model.EntityStatement, error) {
	parts := strings.Split(subordinateStatementJwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT structure")
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %s", err.Error())
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
	var bodyMap map[string]any
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT body: %s", err.Error())
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

	if err = entity_statement.VerifyAgainstJwks(subordinateStatementJwt, sKid, issuer.JWKs); err != nil {
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
func New(ctx context.Context, subjectIdentifier model.EntityIdentifier, subordinateRetriever func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error), configuration model.ServerConfiguration) (*string, error) {
	if configuration.IntermediateConfiguration == nil {
		return nil, fmt.Errorf("no intermediate configuration provided")
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
	}

	subordinateStatementLifetime := configuration.IntermediateConfiguration.SubordinateStatementLifetime
	if subordinateStatementLifetime <= 0 {
		subordinateStatementLifetime = model.DefaultSubordinateStatementLifetime
	}

	subordinateStatement := model.EntityStatement{
		Sub:  subjectIdentifier,
		Iss:  configuration.EntityIdentifier,
		Iat:  time.Now().UTC().Unix(),
		Exp:  time.Now().Add(subordinateStatementLifetime).UTC().Unix(),
		JWKs: subjectSubordinateConfiguration.JWKs,
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

	var roundTrip model.EntityStatement
	if err = json.Unmarshal(subordinateStatementBytes, &roundTrip); err != nil {
		return nil, fmt.Errorf("refusing to publish a subordinate statement this implementation would reject: %s", err.Error())
	}

	return jwt.New(signerConfiguration.Signer, map[string]any{
		"kid": signerConfiguration.KeyID,
		"typ": "entity-statement+jwt",
		"alg": signerConfiguration.Algorithm,
	}, subordinateStatementMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(signerConfiguration.Algorithm)})
}
