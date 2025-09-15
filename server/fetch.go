package server

import (
	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"log/slog"
	"net/http"
)

func (s *Server) Fetch(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")

	if sub == "" {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "request missing required parameter 'sub'"))
	}

	parsedSub, err := model.ValidateEntityIdentifier(sub)
	if err != nil {
		logging.LogInfo(s.l, ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.SubjectNotFoundError())
	}

	if *parsedSub == s.configuration.EntityConfiguration.Iss {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "an entity cannot issue a subordinate statement for itself"))
	}

	token, err := subordinate_statement.New(*parsedSub, s.getSignerForIdentifier(*parsedSub), s.configuration)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error creating subordinate statement", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithEntityStatement(w, []byte(*token))
}
