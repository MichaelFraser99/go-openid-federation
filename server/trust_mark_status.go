package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
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

	var statusMap map[string]any
	if err = json.Unmarshal(statusBytes, &statusMap); err != nil {
		logging.LogInfo(s.l, ctx, "error unmarshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}
	statusMap["iss"] = s.configuration.EntityIdentifier
	statusMap["iat"] = time.Now().UTC().Unix()
	statusMap["trust_mark"] = trustMark

	token, err := jwt.New(s.configuration.SignerConfiguration.Signer, map[string]any{
		"kid": s.configuration.SignerConfiguration.KeyID,
		"typ": "trust-mark-status-response+jwt",
		"alg": s.configuration.SignerConfiguration.Algorithm,
	}, statusMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(s.configuration.SignerConfiguration.Algorithm)})
	if err != nil {
		logging.LogInfo(s.l, ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithTrustMarkStatusResponse(w, []byte(*token))
}
