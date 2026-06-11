package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const trustMarkListingUnavailableError = "unable to list trust marked entities at this time"

func (s *Server) TrustMarkList(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustMarkType := r.URL.Query().Get("trust_mark_type")

	var parsedSub *model.EntityIdentifier
	var err error

	if sub != "" {
		parsedSub, err = model.ValidateEntityIdentifier(sub)
		if err != nil {
			s.cfg.LogInfo(ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'sub' parameter"))
		}
	}

	if trustMarkType == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'trust_mark_type'"))
	}

	status, err := trust_marks.List(ctx, s.cfg, trustMarkType, parsedSub)
	if err != nil {
		s.cfg.LogInfo(ctx, "error listing trust marks", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	statusBytes, err := json.Marshal(status)
	if err != nil {
		s.cfg.LogInfo(ctx, "error marshalling trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(trustMarkListingUnavailableError))
	}

	return s.RespondWithJSON(w, statusBytes)
}
