package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const trustMarkStatusUnavailableError = "unable to list trust mark status at this time"

func (s *Server) TrustMarkStatus(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		s.config().LogInfo(ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("failed to parse request parameters"))
	}
	trustMark := r.PostForm.Get("trust_mark")

	if trustMark == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'trust_mark'"))
	}

	status, err := trust_marks.Status(ctx, *s.config(), trustMark)
	if err != nil {
		classified := s.retrieverError(err, trustMarkStatusUnavailableError)
		s.logFailure(ctx, "error determining trust mark status", classified, slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, classified)
	}

	statusBytes, err := json.Marshal(status)
	if err != nil {
		s.config().LogInfo(ctx, "error marshalling trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(trustMarkStatusUnavailableError))
	}

	var statusMap map[string]any
	if err = json.Unmarshal(statusBytes, &statusMap); err != nil {
		s.config().LogInfo(ctx, "error unmarshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(trustMarkStatusUnavailableError))
	}
	statusMap["iss"] = s.config().EntityIdentifier
	statusMap["iat"] = time.Now().UTC().Unix()
	statusMap["trust_mark"] = trustMark

	if err := model.VerifyIssuanceAlgorithm(s.config().SignerConfiguration.Algorithm); err != nil {
		s.config().LogError(ctx, "the configured signing algorithm cannot be signed with", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(trustMarkStatusUnavailableError))
	}
	token, err := jwt.New(s.config().SignerConfiguration.Signer, map[string]any{
		"kid": s.config().SignerConfiguration.KeyID,
		"typ": "trust-mark-status-response+jwt",
		"alg": s.config().SignerConfiguration.Algorithm,
	}, statusMap, jwt.Opts{Algorithm: jwa.GetAlgorithm(s.config().SignerConfiguration.Algorithm)})
	if err != nil {
		s.config().LogInfo(ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.ClassifySignerError(err, trustMarkStatusUnavailableError))
	}

	return s.RespondWithTrustMarkStatusResponse(w, []byte(*token))
}
