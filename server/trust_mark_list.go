package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func (s *Server) TrustMarkList(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustMarkType := r.URL.Query().Get("trust_mark_type")

	var parsedSub *model.EntityIdentifier
	var err error

	if sub != "" {
		parsedSub, err = model.ValidateEntityIdentifier(sub)
		if err != nil {
			logging.LogInfo(s.l, ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, ferrors.SubjectNotFoundError())
		}
	}

	if trustMarkType == "" {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "request missing required parameter 'trust_mark_type'"))
	}

	status, err := trust_marks.List(ctx, s.l, trustMarkType, parsedSub, s.configuration)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error listing trust marks", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	statusBytes, err := json.Marshal(status)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error marshalling trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithJSON(w, statusBytes)
}
