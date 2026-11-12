package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

const listingUnavailableError = "unable to list subordinate entities at this time"

const subordinateListingUnavailableError = "unable to list subordinate entities at this time"

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
			classified := s.retrieverError(err, subordinateListingUnavailableError)
			s.logFailure(ctx, "error listing subordinates", classified, slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, classified)
		}
		return s.respondWithEntities(ctx, w, identifiers)
	}

	if !filter.IsEmpty() {
		s.cfg.LogInfo(ctx, "received list request with filters but no listing retriever configured")
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("subordinate listing filters are not supported"))
	}

	subordinates, err := s.cfg.GetSubordinates(ctx)
	if err != nil {
		classified := s.retrieverError(err, listingUnavailableError)
		s.logFailure(ctx, "error retrieving subordinates", classified, slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, classified)
	}

	identifiers := make([]model.EntityIdentifier, 0, len(subordinates))
	for identifier := range subordinates {
		identifiers = append(identifiers, identifier)
	}
	return s.respondWithEntities(ctx, w, identifiers)
}

type listingEntries struct {
	seen      map[string]struct{}
	invalid   int
	duplicate int
}

func newListingEntries(size int) *listingEntries {
	return &listingEntries{seen: make(map[string]struct{}, size)}
}

func (l *listingEntries) admit(value any) (string, bool) {
	identifier, _ := value.(string)
	if _, err := model.ValidateEntityIdentifier(identifier); err != nil {
		l.invalid++
		return "", false
	}
	if _, seen := l.seen[identifier]; seen {
		l.duplicate++
		return "", false
	}
	l.seen[identifier] = struct{}{}
	return identifier, true
}

func (s *Server) logOmittedEntries(ctx context.Context, entries *listingEntries) {
	if entries.invalid == 0 && entries.duplicate == 0 {
		return
	}
	s.cfg.LogError(ctx, "omitting listing entries the store returned that are not entity identifiers or repeat one already listed", slog.Int("not_entity_identifiers", entries.invalid), slog.Int("duplicates", entries.duplicate))
}

func (s *Server) respondWithEntities(ctx context.Context, w http.ResponseWriter, identifiers []model.EntityIdentifier) ResponseFunc {
	listed := newListingEntries(len(identifiers))
	entities := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		if admitted, ok := listed.admit(string(identifier)); ok {
			entities = append(entities, admitted)
		}
	}
	s.logOmittedEntries(ctx, listed)
	entitiesJSON, err := json.Marshal(entities)
	if err != nil {
		s.cfg.LogError(ctx, "error marshalling entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(listingUnavailableError))
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
		return nil, errors.New("not a boolean")
	}
	return &parsed, nil
}
