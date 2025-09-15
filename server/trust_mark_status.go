package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
)

func (s *Server) TrustMarkStatus(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	trustMark := r.URL.Query().Get("trust_mark")

	if trustMark == "" {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "request missing required parameter 'trust_mark'"))
	}

	status, err := trust_marks.Status(ctx, s.l, trustMark, s.configuration)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error determining trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	statusBytes, err := json.Marshal(status)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error marshalling trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithJSON(w, statusBytes)
}
