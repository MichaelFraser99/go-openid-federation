package server

import (
	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"log/slog"
	"net/http"
)

func (s *Server) HandleWellKnown(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	entityConfiguration, err := entity_configuration.New(s.configuration)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error generating entity configuration", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}
	return s.RespondWithEntityStatement(w, []byte(*entityConfiguration))
}
