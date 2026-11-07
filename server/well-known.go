package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const entityConfigurationUnavailableError = "unable to produce the entity configuration at this time"

func (s *Server) HandleWellKnown(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	entityConfiguration, err := s.newEntityConfiguration(ctx)
	if err != nil {
		classified := s.retrieverError(err, entityConfigurationUnavailableError)
		s.logFailure(ctx, "error generating entity cfg", classified, slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, classified)
	}
	return s.RespondWithEntityStatement(w, []byte(*entityConfiguration))
}

func (s *Server) newEntityConfiguration(ctx context.Context) (*string, error) {
	cfg := s.cfg
	cfg.AuthorityHints = s.AuthorityHints()
	return entity_configuration.New(ctx, cfg)
}

func (s *Server) ownEntityConfiguration(ctx context.Context) (*string, *model.EntityStatement, error) {
	signed, err := s.newEntityConfiguration(ctx)
	if err != nil {
		s.cfg.LogError(ctx, "this server could not produce its own entity configuration for a trust chain walk", slog.String("error", err.Error()))
		return nil, nil, model.ClassifySignerError(err, entityConfigurationUnavailableError)
	}
	accepted, statement, err := entity_configuration.Accept(ctx, s.cfg.Configuration, s.cfg.EntityIdentifier, *signed)
	if err != nil {
		s.cfg.LogError(ctx, "this server's own entity configuration does not pass the checks a resolver applies to it", slog.String("error", err.Error()))
		return nil, nil, model.NewServerError(entityConfigurationUnavailableError)
	}
	return accepted, statement, nil
}
