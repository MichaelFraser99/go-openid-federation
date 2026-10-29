package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const subordinateStatusUnavailableError = "unable to retrieve subordinate entity statuses at this time"

func (s *Server) SubordinateStatus(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()

	s.cfg.LogInfo(ctx, "received subordinate status request")

	if !s.cfg.Extensions.SubordinateStatus.Enabled {
		return s.RespondWithError(ctx, w, model.NewServerError("subordinate status not enabled"))
	}
	if s.cfg.Extensions.SubordinateStatus.MetadataRetriever == nil {
		return s.RespondWithError(ctx, w, model.NewServerError("subordinate status metadata retriever not configured"))
	}

	err := r.ParseForm()
	if err != nil {
		s.cfg.LogInfo(ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("failed to parse request parameters"))
	}
	sub := r.URL.Query().Get("sub")

	s.cfg.LogInfo(ctx, "processing subordinate status request for specified entity", slog.String("sub", sub))

	var parsedSubject *model.EntityIdentifier

	if sub != "" {
		parsedSubject, err = s.resolveEntityIdentifier(ctx, model.EntityIdentifierParamSub, sub)
		if err != nil {
			s.cfg.LogInfo(ctx, "error parsing 'sub' parameter as an entity identifier", slog.String("error", err.Error()))
			return s.RespondWithError(ctx, w, err)
		}
	} else {
		s.cfg.LogInfo(ctx, "request missing required parameter 'sub'")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}

	status, err := s.cfg.Extensions.SubordinateStatus.MetadataRetriever.GetSubordinateStatus(ctx, *parsedSubject)
	if err != nil {
		s.cfg.LogInfo(ctx, "error retrieving subordinate status", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, s.retrieverError(err, subordinateStatusUnavailableError))
	}

	if status == nil {
		s.cfg.LogInfo(ctx, "subordinate status retriever returned no status and no error, treating the entity as unknown", slog.String("sub", string(*parsedSubject)))
		return s.RespondWithError(ctx, w, model.NewNotFoundError("unknown entity identifier"))
	}

	response := *status
	if response.Events == nil {
		response.Events = []model.SubordinateStatusEvent{}
	}

	statusBytes, err := json.Marshal(response)
	if err != nil {
		s.cfg.LogInfo(ctx, "error marshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(subordinateStatusUnavailableError))
	}

	var statusMap map[string]any
	if err = json.Unmarshal(statusBytes, &statusMap); err != nil {
		s.cfg.LogInfo(ctx, "error unmarshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(subordinateStatusUnavailableError))
	}
	statusMap["sub"] = *parsedSubject
	statusMap["iss"] = s.cfg.EntityIdentifier
	statusMap["iat"] = time.Now().UTC().Unix()
	if s.cfg.Extensions.SubordinateStatus.ResponseLifetime != nil {
		statusMap["exp"] = time.Now().Add(*s.cfg.Extensions.SubordinateStatus.ResponseLifetime).UTC().Unix()
	}

	token, err := jwt.New(s.cfg.SignerConfiguration.Signer, map[string]any{
		"kid": s.cfg.SignerConfiguration.KeyID,
		"typ": "entity-events-statement+jwt",
		"alg": s.cfg.SignerConfiguration.Algorithm,
	}, statusMap, jwt.Opts{Algorithm: jwa.GetAlgorithm(s.cfg.SignerConfiguration.Algorithm)})
	if err != nil {
		s.cfg.LogInfo(ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.ClassifySignerError(err, subordinateStatusUnavailableError))
	}

	return s.RespondWithSubordinateStatementResponse(w, []byte(*token))
}
