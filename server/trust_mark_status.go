package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const trustMarkStatusUnavailableError = "unable to list trust mark status at this time"

func (s *Server) TrustMarkStatus(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	trustMark := r.URL.Query().Get("trust_mark")

	if trustMark == "" {
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'trust_mark'"))
	}

	status, err := trust_marks.Status(ctx, s.cfg, trustMark)
	if err != nil {
		s.cfg.LogInfo(ctx, "error determining trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	statusBytes, err := json.Marshal(status)
	if err != nil {
		s.cfg.LogInfo(ctx, "error marshalling trust mark status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(trustMarkStatusUnavailableError))
	}

	var statusMap map[string]any
	if err = json.Unmarshal(statusBytes, &statusMap); err != nil {
		s.cfg.LogInfo(ctx, "error unmarshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(trustMarkStatusUnavailableError))
	}
	statusMap["iss"] = s.cfg.EntityIdentifier
	statusMap["iat"] = time.Now().UTC().Unix()
	statusMap["trust_mark"] = trustMark

	token, err := jwt.New(s.cfg.SignerConfiguration.Signer, map[string]any{
		"kid": s.cfg.SignerConfiguration.KeyID,
		"typ": "trust-mark-status-response+jwt",
		"alg": s.cfg.SignerConfiguration.Algorithm,
	}, statusMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(s.cfg.SignerConfiguration.Algorithm)})
	if err != nil {
		s.cfg.LogInfo(ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(trustMarkStatusUnavailableError))
	}

	return s.RespondWithTrustMarkStatusResponse(w, []byte(*token))
}
