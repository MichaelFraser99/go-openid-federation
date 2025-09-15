package server

import (
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func (s *Server) TrustMark(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustMarkType := r.URL.Query().Get("trust_mark_type")

	if sub == "" {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "request missing required parameter 'sub'"))
	}

	parsedSub, err := model.ValidateEntityIdentifier(sub)
	if err != nil {
		logging.LogInfo(s.l, ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.SubjectNotFoundError())
	}

	if trustMarkType == "" {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "request missing required parameter 'trust_mark_type'"))
	}

	trustMark, err := trust_marks.Issue(ctx, s.l, trustMarkType, *parsedSub, s.configuration)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error listing trust marks", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithTrustMark(w, []byte(*trustMark))
}
