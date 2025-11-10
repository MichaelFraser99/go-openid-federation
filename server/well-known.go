package server

import (
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
)

func (s *Server) HandleWellKnown(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	entityConfiguration, err := entity_configuration.New(ctx, s.cfg)
	if err != nil {
		s.cfg.LogInfo(ctx, "error generating entity cfg", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}
	return s.RespondWithEntityStatement(w, []byte(*entityConfiguration))
}
