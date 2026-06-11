package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

const listingUnavailableError = "unable to list subordinate entities at this time"

func (s *Server) List(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	entityType := r.URL.Query().Get("entity_type")        //todo
	trustMarked := r.URL.Query().Get("trust_marked")      //todo
	trustMarkType := r.URL.Query().Get("trust_mark_type") //todo
	intermediate := r.URL.Query().Get("intermediate")     //todo: consider supporting - we likely won't - stupid parameter

	if entityType != "" {
		s.cfg.LogInfo(ctx, "received list request with unsupported parameter 'entity_type'", slog.String("entity_type", entityType))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'entity_type' is not supported"))
	}
	if trustMarked != "" {
		s.cfg.LogInfo(ctx, "received list request with unsupported parameter 'trust_marked'", slog.String("trust_marked", trustMarked))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'trust_marked' is not supported"))
	}
	if trustMarkType != "" {
		s.cfg.LogInfo(ctx, "received list request with unsupported parameter 'trust_mark_type'", slog.String("trust_mark_type", trustMarkType))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'trust_mark_type' is not supported"))
	}
	if intermediate != "" {
		s.cfg.LogInfo(ctx, "received list request with unsupported parameter 'intermediate'", slog.String("intermediate", intermediate))
		return s.RespondWithError(ctx, w, model.NewUnsupportedParameterError("parameter 'intermediate' is not supported"))
	}

	if s.cfg.IntermediateConfiguration == nil {
		return s.RespondWithJSON(w, []byte(`[]`))
	}
	var entities []string

	subordinates, err := s.cfg.GetSubordinates(ctx)
	if err != nil {
		s.cfg.LogError(ctx, "error retrieving subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(listingUnavailableError))
	}
	for identifier := range subordinates {
		entities = append(entities, string(identifier))
	}

	entitiesJSON, err := json.Marshal(entities)
	if err != nil {
		s.cfg.LogError(ctx, "error marshalling entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(listingUnavailableError))
	}
	return s.RespondWithJSON(w, entitiesJSON)
}
