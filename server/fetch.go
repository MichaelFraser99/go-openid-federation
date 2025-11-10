package server

import (
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func (s *Server) Fetch(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")

	if sub == "" {
		s.cfg.LogInfo(ctx, "no sub query parameter found")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}

	parsedSub, err := model.ValidateEntityIdentifier(sub)
	if err != nil {
		s.cfg.LogInfo(ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'sub' parameter"))
	}

	if *parsedSub == s.cfg.EntityConfiguration.Iss {
		s.cfg.LogInfo(ctx, "provided 'sub' parameter matches server entity identifier")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("an entity cannot issue a subordinate statement for itself"))
	}

	token, err := subordinate_statement.New(ctx, *parsedSub, s.loadSubordinate(ctx, *parsedSub), s.cfg)
	if err != nil {
		s.cfg.LogInfo(ctx, "error creating subordinate statement", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	return s.RespondWithEntityStatement(w, []byte(*token))
}
