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

	err := r.ParseForm()
	if err != nil {
		s.cfg.LogInfo(ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("failed to parse request form"))
	}
	fromEntityID := r.URL.Query().Get("from_entity_id")
	limit := r.URL.Query().Get("limit")
	updatedAfter := r.URL.Query().Get("updated_after")   //todo
	updatedBefore := r.URL.Query().Get("updated_before") //todo
	claims := r.URL.Query().Get("claims")
	auditTimestamps := r.URL.Query().Get("audit_timestamps") //todo

	var (
		parsedLimit           int
		parsedFromEntityID    *model.EntityIdentifier
		parsedRequestedClaims []string
	)

	if fromEntityID != "" {
		parsedFromEntityID, err = model.ValidateEntityIdentifier(fromEntityID)
		if err != nil {
			s.cfg.LogInfo(ctx, "error parsing 'from_entity_id' parameter", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'from_entity_id' parameter"))
		}
	}
	if limit != "" {
		parsedLimit, err = strconv.Atoi(limit)
		if err != nil {
			s.cfg.LogInfo(ctx, "error parsing 'limit' parameter", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'limit' parameter"))
		}
	} else {
		parsedLimit = s.cfg.Extensions.ExtendedListing.SizeLimit
	}
	if claims != "" {
		split := strings.Split(claims, ",")
		parsedRequestedClaims = make([]string, len(split))
		for i, claim := range split {
			parsedRequestedClaims[i] = strings.TrimSpace(claim)
		}
	}

	var subordinateStatement bool
	if subordinateStatement = slices.Contains(parsedRequestedClaims, "subordinate_statement"); subordinateStatement {
		parsedRequestedClaims = slices.DeleteFunc(parsedRequestedClaims, func(val string) bool {
			return val == "subordinate_statement"
		})
	}

	if updatedAfter != "" {
		s.cfg.LogInfo(ctx, "parameter 'updated_after' is not supported", slog.String("value", updatedAfter))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'updated_after' is not supported"))
	}
	if updatedBefore != "" {
		s.cfg.LogInfo(ctx, "parameter 'updated_before' is not supported", slog.String("value", updatedBefore))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'updated_before' is not supported"))
	}
	if auditTimestamps != "" {
		s.cfg.LogInfo(ctx, "parameter 'audit_timestamps' is not supported", slog.String("value", auditTimestamps))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'audit_timestamps' is not supported"))
	}

	subordinates, err := s.cfg.Extensions.ExtendedListing.MetadataRetriever.GetExtendedSubordinates(ctx, parsedFromEntityID, parsedLimit, parsedRequestedClaims)
	if err != nil {
		s.cfg.LogError(ctx, "error getting subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
	}

	if len(subordinates.ImmediateSubordinateEntities) == 0 {
		return s.RespondWithJSON(w, []byte(`{"immediate_subordinate_entities":[]}`))
	}

	if parsedFromEntityID != nil && subordinates.ImmediateSubordinateEntities[0]["id"] != fromEntityID {
		s.cfg.LogError(ctx, "first entity identifier retrieved from configured metadata retriever does not match the requested value", slog.String("received", subordinates.ImmediateSubordinateEntities[0]["id"].(string)), slog.String("requested", fromEntityID))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(extendedListingUnavailableError))
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
