package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const extendedListingMalformedIdentifierError = "one or more subordinate entities has a missing or malformed 'id'"

const extendedListingUnavailableError = "unable to list extended subordinate entities at this time"

func (s *Server) ExtendedList(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	if !s.cfg.Extensions.ExtendedListing.Enabled {
		return s.RespondWithError(ctx, w, model.NewServerError("extended subordinate listing not enabled"))
	}
	if s.cfg.Extensions.ExtendedListing.MetadataRetriever == nil {
		return s.RespondWithError(ctx, w, model.NewServerError("extended subordinate listing metadata retriever not configured"))
	}
	if s.cfg.Extensions.ExtendedListing.SizeLimit <= 0 {
		return s.RespondWithError(ctx, w, model.NewServerError("extended subordinate listing size limit not configured"))
	}

	if err := r.ParseForm(); err != nil {
		s.cfg.LogInfo(ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("failed to parse request form"))
	}

	filter, subordinateStatement, err := parseExtendedListingFilter(r.URL.Query(), s.cfg.Extensions.ExtendedListing.SizeLimit)
	if err != nil {
		s.cfg.LogInfo(ctx, "received extended list request with malformed filter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	subordinates, err := s.cfg.Extensions.ExtendedListing.MetadataRetriever.GetExtendedSubordinates(ctx, filter)
	if err != nil {
		err = s.retrieverError(err, extendedListingUnavailableError)
		s.cfg.LogError(ctx, "error getting subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	if subordinates == nil {
		s.cfg.LogError(ctx, "extended listing retriever returned a nil response with no error, this is a result of mis-configuration")
		return s.RespondWithError(ctx, w, model.NewServerError(extendedListingUnavailableError))
	}

	response := *subordinates
	if response.ImmediateSubordinateEntities == nil {
		response.ImmediateSubordinateEntities = []map[string]any{}
	}

	if subordinateStatement {
		for i, subordinateEntity := range response.ImmediateSubordinateEntities {
			identifier, ok := subordinateEntity["id"].(string)
			if !ok {
				s.cfg.LogError(ctx, "missing or malformed 'id' field in one or more subordinate entities, this is a result of mis-configuration")
				return s.RespondWithError(ctx, w, model.NewServerError(extendedListingMalformedIdentifierError))
			}

			parsedIdentifier, err := model.ValidateEntityIdentifier(identifier)
			if err != nil {
				s.cfg.LogError(ctx, "invalid 'id' parameter included in retrieved list response, this is a result of mis-configuration", slog.String("error", err.Error()))
				return s.RespondWithError(ctx, w, model.NewServerError(extendedListingUnavailableError))
			}

			//todo: this is going to need some form of caching mechanism to not be extremely expensive to run - we might want to drop this parameter from the draft
			token, err := subordinate_statement.New(ctx, *parsedIdentifier, s.loadSubordinate(ctx, *parsedIdentifier), s.cfg)
			if err != nil {
				if !errors.Is(err, model.ErrNotFound) && !errors.Is(err, model.ErrInvalidSubject) {
					s.cfg.LogError(ctx, "error creating subordinate statement", slog.String("error", err.Error()))
					return s.RespondWithError(ctx, w, s.retrieverError(err, extendedListingUnavailableError))
				}
				s.cfg.LogInfo(ctx, "omitting the subordinate statement for an entity it could not be issued for", slog.String("sub", identifier), slog.String("error", err.Error()))
			} else {
				response.ImmediateSubordinateEntities[i]["subordinate_statement"] = *token
			}
		}
	}

	entitiesJSON, err := json.Marshal(response)
	if err != nil {
		s.cfg.LogError(ctx, "error marshalling subordinate entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
	}
	return s.RespondWithJSON(w, entitiesJSON)
}

const maxRequestedClaims = 64

func parseExtendedListingFilter(query map[string][]string, defaultLimit int) (model.ExtendedListingFilter, bool, error) {
	filter := model.ExtendedListingFilter{
		EntityTypes:   query["entity_type"],
		TrustMarkType: query["trust_mark_type"],
		Limit:         defaultLimit,
	}

	trustMarked, err := parseOptionalBool(getSingle(query, "trust_marked"))
	if err != nil {
		return filter, false, model.NewInvalidRequestError("parameter 'trust_marked' must be a boolean")
	}
	filter.TrustMarked = trustMarked

	intermediate, err := parseOptionalBool(getSingle(query, "intermediate"))
	if err != nil {
		return filter, false, model.NewInvalidRequestError("parameter 'intermediate' must be a boolean")
	}
	filter.Intermediate = intermediate

	if from := getSingle(query, "from"); from != "" {
		filter.From = new(from)
	}

	if limit := getSingle(query, "limit"); limit != "" {
		parsedLimit, err := strconv.Atoi(limit)
		if err != nil {
			return filter, false, model.NewInvalidRequestError("malformed 'limit' parameter")
		}
		if parsedLimit <= 0 {
			return filter, false, model.NewInvalidRequestError("parameter 'limit' must be a positive integer")
		}
		filter.Limit = min(parsedLimit, defaultLimit)
	}

	for _, unsupported := range []string{"updated_after", "updated_before", "audit_timestamps"} {
		if value := getSingle(query, unsupported); value != "" {
			return filter, false, model.NewUnsupportedParameterError("parameter '" + unsupported + "' is not supported")
		}
	}

	var subordinateStatement bool
	requestedClaims := make([]string, 0, maxRequestedClaims)
	seenClaims := make(map[string]struct{}, maxRequestedClaims)
	for _, claims := range query["claims"] {
		for _, claim := range strings.Split(claims, ",") {
			trimmed := strings.TrimSpace(claim)
			if trimmed == "" {
				continue
			}
			if _, seen := seenClaims[trimmed]; seen {
				continue
			}
			if len(seenClaims) == maxRequestedClaims {
				return filter, false, model.NewInvalidRequestError(fmt.Sprintf("parameter 'claims' names more than %d claims", maxRequestedClaims))
			}
			seenClaims[trimmed] = struct{}{}
			requestedClaims = append(requestedClaims, trimmed)
		}
	}
	if len(requestedClaims) > 0 {
		if subordinateStatement = slices.Contains(requestedClaims, "subordinate_statement"); subordinateStatement {
			requestedClaims = slices.DeleteFunc(requestedClaims, func(val string) bool {
				return val == "subordinate_statement"
			})
		}
		filter.Claims = requestedClaims
	}

	return filter, subordinateStatement, nil
}
