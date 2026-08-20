package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const extendedListingUnavailableError = "unable to list extended subordinate entities at this time"

func (s *Server) ExtendedList(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	if !s.cfg.Extensions.ExtendedListing.Enabled {
		return s.RespondWithError(ctx, w, model.NewServerError("extended subordinate listing not enabled"))
	}
	if s.cfg.Extensions.ExtendedListing.MetadataRetriever == nil {
		return s.RespondWithError(ctx, w, model.NewServerError("extended subordinate listing metadata retriever not configured"))
	}
	if s.cfg.Extensions.ExtendedListing.SizeLimit == 0 {
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
		s.cfg.LogError(ctx, "error getting subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
	}

	if len(subordinates.ImmediateSubordinateEntities) == 0 {
		return s.RespondWithJSON(w, []byte(`{"immediate_subordinate_entities":[]}`))
	}

	if subordinateStatement {
		for i, subordinateEntity := range subordinates.ImmediateSubordinateEntities {
			if _, ok := subordinateEntity["id"]; !ok {
				s.cfg.LogError(ctx, "missing 'id' field in one or more subordinate entities")
				return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
			}

			parsedIdentifier, err := model.ValidateEntityIdentifier(subordinateEntity["id"].(string))
			if err != nil {
				s.cfg.LogError(ctx, "invalid 'id' parameter included in retrieved list response", slog.String("error", err.Error()))
				return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
			}

			//todo: this is going to need some form of caching mechanism to not be extremely expensive to run - we might want to drop this parameter from the draft
			token, err := subordinate_statement.New(ctx, *parsedIdentifier, s.loadSubordinate(ctx, *parsedIdentifier), s.cfg)
			if err != nil {
				if err.Error() != "unknown entity identifier" {
					s.cfg.LogError(ctx, "error creating subordinate statement", slog.String("error", err.Error()))
					return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
				}
			} else {
				subordinates.ImmediateSubordinateEntities[i]["subordinate_statement"] = *token
			}
		}
	}

	entitiesJSON, err := json.Marshal(*subordinates)
	if err != nil {
		s.cfg.LogError(ctx, "error marshalling subordinate entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
	}
	return s.RespondWithJSON(w, entitiesJSON)
}

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

	if fromEntityID := getSingle(query, "from_entity_id"); fromEntityID != "" {
		parsedFromEntityID, err := model.ValidateEntityIdentifier(fromEntityID)
		if err != nil {
			return filter, false, model.NewInvalidRequestError("malformed 'from_entity_id' parameter")
		}
		filter.From = parsedFromEntityID
	}

	if limit := getSingle(query, "limit"); limit != "" {
		parsedLimit, err := strconv.Atoi(limit)
		if err != nil {
			return filter, false, model.NewInvalidRequestError("malformed 'limit' parameter")
		}
		filter.Limit = parsedLimit
	}

	for _, unsupported := range []string{"updated_after", "updated_before", "audit_timestamps"} {
		if value := getSingle(query, unsupported); value != "" {
			return filter, false, model.NewUnsupportedParameterError("parameter '" + unsupported + "' is not supported")
		}
	}

	var subordinateStatement bool
	if claims := getSingle(query, "claims"); claims != "" {
		split := strings.Split(claims, ",")
		requestedClaims := make([]string, 0, len(split))
		for _, claim := range split {
			requestedClaims = append(requestedClaims, strings.TrimSpace(claim))
		}
		if subordinateStatement = slices.Contains(requestedClaims, "subordinate_statement"); subordinateStatement {
			requestedClaims = slices.DeleteFunc(requestedClaims, func(val string) bool {
				return val == "subordinate_statement"
			})
		}
		filter.Claims = requestedClaims
	}

	return filter, subordinateStatement, nil
}
