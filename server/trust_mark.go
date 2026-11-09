package server

import (
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const trustMarkUnavailableError = "unable to issue the trust mark at this time"

func (s *Server) TrustMark(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustMarkType := r.URL.Query().Get("trust_mark_type")

	if sub == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}

	parsedSub, err := s.resolveEntityIdentifier(ctx, model.EntityIdentifierParamSub, sub, trustMarkUnavailableError)
	if err != nil {
		return s.RespondWithError(ctx, w, err)
	}

	if trustMarkType == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'trust_mark_type'"))
	}

	trustMark, err := trust_marks.Issue(ctx, s.cfg, trustMarkType, *parsedSub)
	if err != nil {
		classified := s.retrieverError(err, trustMarkUnavailableError)
		s.logFailure(ctx, "error issuing the trust mark", classified, slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, classified)
	}

	return s.RespondWithTrustMark(w, []byte(*trustMark))
}
