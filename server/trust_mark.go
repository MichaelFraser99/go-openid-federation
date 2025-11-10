package server

import (
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func (s *Server) TrustMark(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustMarkType := r.URL.Query().Get("trust_mark_type")

	if sub == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}

	parsedSub, err := model.ValidateEntityIdentifier(sub)
	if err != nil {
		s.cfg.LogInfo(ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'sub' parameter"))
	}

	if trustMarkType == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'trust_mark_type'"))
	}

	trustMark, err := trust_marks.Issue(ctx, s.cfg, trustMarkType, *parsedSub)
	if err != nil {
		s.cfg.LogInfo(ctx, "error listing trust marks", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	return s.RespondWithTrustMark(w, []byte(*trustMark))
}
