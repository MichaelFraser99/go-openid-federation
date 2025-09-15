package server

import (
	"encoding/json"
	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

func (s *Server) ExtendedList(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	if !s.configuration.Extensions.ExtendedListing.Enabled {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.ServerError, "extended subordinate listing not enabled"))
	}
	if s.configuration.Extensions.ExtendedListing.MetadataRetriever == nil {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.ServerError, "extended subordinate listing metadata retriever not configured"))
	}
	if s.configuration.Extensions.ExtendedListing.SizeLimit == 0 {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.ServerError, "extended subordinate listing size limit not configured"))
	}

	err := r.ParseForm()
	if err != nil {
		logging.LogInfo(s.l, ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "failed to parse request form"))
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
			logging.LogInfo(s.l, ctx, "error parsing 'from_entity_id' parameter", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
		}
	}
	if limit != "" {
		parsedLimit, err = strconv.Atoi(limit)
		if err != nil {
			logging.LogInfo(s.l, ctx, "error parsing 'limit' parameter", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "unable to parse 'limit' parameter"))
		}
	} else {
		parsedLimit = s.configuration.Extensions.ExtendedListing.SizeLimit
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
		logging.LogInfo(s.l, ctx, "parameter 'updated_after' is not supported", slog.String("value", updatedAfter))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'updated_after' is not supported"))
	}
	if updatedBefore != "" {
		logging.LogInfo(s.l, ctx, "parameter 'updated_before' is not supported", slog.String("value", updatedBefore))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'updated_before' is not supported"))
	}
	if auditTimestamps != "" {
		logging.LogInfo(s.l, ctx, "parameter 'audit_timestamps' is not supported", slog.String("value", auditTimestamps))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'audit_timestamps' is not supported"))
	}

	subordinates, err := s.configuration.Extensions.ExtendedListing.MetadataRetriever.GetExtendedSubordinates(parsedFromEntityID, parsedLimit, parsedRequestedClaims)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error getting subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	if len(subordinates.ImmediateSubordinateEntities) == 0 {
		return s.RespondWithJSON(w, []byte(`{"immediate_subordinate_entities":[]}`))
	}

	if parsedFromEntityID != nil && subordinates.ImmediateSubordinateEntities[0]["id"] != fromEntityID {
		logging.LogInfo(s.l, ctx, "first entity identifier retrieved from configured metadata retriever does not match the requested value", slog.String("received", subordinates.ImmediateSubordinateEntities[0]["id"].(string)), slog.String("requested", fromEntityID))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	if subordinateStatement {
		for i, subordinateEntity := range subordinates.ImmediateSubordinateEntities {
			if _, ok := subordinateEntity["id"]; !ok {
				logging.LogInfo(s.l, ctx, "missing 'id' field in one or more subordinate entities")
				return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
			}

			parsedIdentifier, err := model.ValidateEntityIdentifier(subordinateEntity["id"].(string))
			if err != nil {
				logging.LogInfo(s.l, ctx, "invalid 'id' parameter included in retrieved list response", slog.String("error", err.Error()))
				return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
			}

			token, err := subordinate_statement.New(*parsedIdentifier, s.getSignerForIdentifier(*parsedIdentifier), s.configuration)
			if err != nil {
				if err.Error() != "unknown entity identifier" {
					logging.LogInfo(s.l, ctx, "error creating subordinate statement", slog.String("error", err.Error()))
					return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
				}
			} else {
				subordinates.ImmediateSubordinateEntities[i]["subordinate_statement"] = *token
			}
		}
	}

	entitiesJSON, err := json.Marshal(*subordinates)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error marshalling subordinate entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}
	return s.RespondWithJSON(w, entitiesJSON)
}
