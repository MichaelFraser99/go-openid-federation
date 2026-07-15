package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

const listingUnavailableError = "unable to list subordinate entities at this time"

func (s *Server) List(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	filter, err := parseSubordinateListingFilter(r.URL.Query())
	if err != nil {
		s.cfg.LogInfo(ctx, "received list request with malformed filter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	if s.cfg.IntermediateConfiguration == nil {
		return s.RespondWithJSON(w, []byte(`[]`))
	}

	if listingRetriever, ok := s.cfg.MetadataRetriever.(model.SubordinateListingRetriever); ok {
		identifiers, err := listingRetriever.ListSubordinates(ctx, filter)
		if err != nil {
			s.cfg.LogInfo(ctx, "error listing subordinates", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, err)
		}
		return s.respondWithEntities(ctx, w, identifiers)
	}

	if !filter.IsEmpty() {
		s.cfg.LogInfo(ctx, "received list request with filters but no listing retriever configured")
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("subordinate listing filters are not supported"))
	}

	subordinates, err := s.cfg.GetSubordinates(ctx)
	if err != nil {
		s.cfg.LogError(ctx, "error retrieving subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(listingUnavailableError))
	}

	identifiers := make([]model.EntityIdentifier, 0, len(subordinates))
	for identifier := range subordinates {
		identifiers = append(identifiers, identifier)
	}
	return s.respondWithEntities(ctx, w, identifiers)
}

func (s *Server) respondWithEntities(ctx context.Context, w http.ResponseWriter, identifiers []model.EntityIdentifier) ResponseFunc {
	entities := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		entities = append(entities, string(identifier))
	}
	entitiesJSON, err := json.Marshal(entities)
	if err != nil {
		s.cfg.LogError(ctx, "error marshalling entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(listingUnavailableError))
	}
	return s.RespondWithJSON(w, entitiesJSON)
}

func parseSubordinateListingFilter(query map[string][]string) (model.SubordinateListingFilter, error) {
	filter := model.SubordinateListingFilter{
		EntityTypes: query["entity_type"],
	}

	if trustMarkType := getSingle(query, "trust_mark_type"); trustMarkType != "" {
		filter.TrustMarkType = &trustMarkType
	}

	trustMarked, err := parseOptionalBool(getSingle(query, "trust_marked"))
	if err != nil {
		return filter, model.NewInvalidRequestError("parameter 'trust_marked' must be a boolean")
	}
	filter.TrustMarked = trustMarked

	intermediate, err := parseOptionalBool(getSingle(query, "intermediate"))
	if err != nil {
		return filter, model.NewInvalidRequestError("parameter 'intermediate' must be a boolean")
	}
	filter.Intermediate = intermediate

	return filter, nil
}

func getSingle(query map[string][]string, key string) string {
	if values := query[key]; len(values) > 0 {
		return values[0]
	}
	return ""
}

func parseOptionalBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
