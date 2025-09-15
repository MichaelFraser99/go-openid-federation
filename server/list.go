package server

import (
	"encoding/json"
	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"log/slog"
	"net/http"
)

func (s *Server) List(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	entityType := r.URL.Query().Get("entity_type")        //todo
	trustMarked := r.URL.Query().Get("trust_marked")      //todo
	trustMarkType := r.URL.Query().Get("trust_mark_type") //todo
	intermediate := r.URL.Query().Get("intermediate")     //todo: consider supporting - we likely won't - stupid parameter

	if entityType != "" {
		logging.LogInfo(s.l, ctx, "received list request with unsupported parameter 'entity_type'", slog.String("entity_type", entityType))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'entity_type' is not supported"))
	}
	if trustMarked != "" {
		logging.LogInfo(s.l, ctx, "received list request with unsupported parameter 'trust_marked'", slog.String("trust_marked", trustMarked))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'trust_marked' is not supported"))
	}
	if trustMarkType != "" {
		logging.LogInfo(s.l, ctx, "received list request with unsupported parameter 'trust_mark_type'", slog.String("trust_mark_type", trustMarkType))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'trust_mark_type' is not supported"))
	}
	if intermediate != "" {
		logging.LogInfo(s.l, ctx, "received list request with unsupported parameter 'intermediate'", slog.String("intermediate", intermediate))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.UnsupportedParameterError, "parameter 'intermediate' is not supported"))
	}

	if s.configuration.IntermediateConfiguration == nil {
		return s.RespondWithJSON(w, []byte(`[]`))
	}
	var entities []string

	subordinates, err := s.configuration.GetSubordinates()
	if err != nil {
		logging.LogInfo(s.l, ctx, "error retrieving subordinates", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}
	for identifier := range subordinates {
		entities = append(entities, string(identifier))
	}

	entitiesJSON, err := json.Marshal(entities)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error marshalling entities", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}
	return s.RespondWithJSON(w, entitiesJSON)
}
