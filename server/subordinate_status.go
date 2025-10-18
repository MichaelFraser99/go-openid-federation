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
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func (s *Server) SubordinateStatus(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	logging.LogInfo(s.l, ctx, "received subordinate status request")

	if !s.configuration.Extensions.SubordinateStatus.Enabled {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.ServerError, "subordinate status not enabled"))
	}
	if s.configuration.Extensions.SubordinateStatus.MetadataRetriever == nil {
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.ServerError, "subordinate status metadata retriever not configured"))
	}

	err := r.ParseForm()
	if err != nil {
		logging.LogInfo(s.l, ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "failed to parse request form"))
	}
	sub := r.URL.Query().Get("sub")

	logging.LogInfo(s.l, ctx, "processing subordinate status request for specified entity", slog.String("sub", sub))

	var parsedSubject *model.EntityIdentifier

	if sub != "" {
		parsedSubject, err = model.ValidateEntityIdentifier(sub)
		if err != nil {
			logging.LogInfo(s.l, ctx, "error parsing 'sub' parameter as an entity identifier", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
		}
	} else {
		logging.LogInfo(s.l, ctx, "request missing required parameter 'sub'")
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "request missing required parameter 'sub'"))
	}

	status, err := s.configuration.Extensions.SubordinateStatus.MetadataRetriever.GetSubordinateStatus(parsedSubject)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error retrieving subordinate status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	statusBytes, err := json.Marshal(status)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error marshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	var statusMap map[string]any
	if err = json.Unmarshal(statusBytes, &statusMap); err != nil {
		logging.LogInfo(s.l, ctx, "error unmarshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}
	statusMap["sub"] = *parsedSubject
	statusMap["iss"] = s.configuration.EntityIdentifier
	statusMap["iat"] = time.Now().UTC().Unix()
	if s.configuration.Extensions.SubordinateStatus.ResponseLifetime != nil {
		statusMap["exp"] = time.Now().Add(*s.configuration.Extensions.SubordinateStatus.ResponseLifetime).UTC().Unix()
	}

	token, err := jwt.New(s.configuration.SignerConfiguration.Signer, map[string]any{
		"kid": s.configuration.SignerConfiguration.KeyID,
		"typ": "entity-events-statement+jwt",
		"alg": s.configuration.SignerConfiguration.Algorithm,
	}, statusMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(s.configuration.SignerConfiguration.Algorithm)})
	if err != nil {
		logging.LogInfo(s.l, ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithSubordinateStatementResponse(w, []byte(*token))
}
