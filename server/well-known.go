package server

import (
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
)

const entityConfigurationUnavailableError = "unable to produce the entity configuration at this time"

func (s *Server) HandleWellKnown(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	cfg := s.cfg
	cfg.AuthorityHints = s.AuthorityHints()

	entityConfiguration, err := entity_configuration.New(ctx, cfg)
	if err != nil {
		s.cfg.LogInfo(ctx, "error generating entity cfg", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, s.retrieverError(err, entityConfigurationUnavailableError))
	}
	return s.RespondWithEntityStatement(w, []byte(*entityConfiguration))
}
