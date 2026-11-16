package server

import (
	"encoding/json"
	"fmt"
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

	s.config().LogInfo(ctx, "received subordinate status request")

	if !s.config().Extensions.SubordinateStatus.Enabled {
		return s.respondWithMisconfiguration(ctx, w, "subordinate status not enabled", subordinateStatusUnavailableError)
	}
	if s.config().Extensions.SubordinateStatus.MetadataRetriever == nil {
		return s.respondWithMisconfiguration(ctx, w, "subordinate status metadata retriever not configured", subordinateStatusUnavailableError)
	}
	if lifetime := s.config().Extensions.SubordinateStatus.ResponseLifetime; lifetime != nil && *lifetime < time.Second {
		return s.respondWithMisconfiguration(ctx, w, fmt.Sprintf("subordinate status response lifetime must be at least one second, got %s", *lifetime), subordinateStatusUnavailableError)
	}

	err := r.ParseForm()
	if err != nil {
		s.config().LogInfo(ctx, "error parsing request", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("failed to parse request parameters"))
	}
	sub := r.URL.Query().Get("sub")

	s.config().LogInfo(ctx, "processing subordinate status request for specified entity", slog.String("sub", sub))

	var parsedSubject *model.EntityIdentifier

	if sub != "" {
		parsedSubject, err = s.resolveEntityIdentifier(ctx, model.EntityIdentifierParamSub, sub, subordinateStatusUnavailableError)
		if err != nil {
			return s.RespondWithError(ctx, w, err)
		}
	} else {
		s.config().LogInfo(ctx, "request missing required parameter 'sub'")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}

	status, err := s.config().Extensions.SubordinateStatus.MetadataRetriever.GetSubordinateStatus(ctx, *parsedSubject)
	if err != nil {
		classified := s.retrieverError(err, subordinateStatusUnavailableError)
		s.logFailure(ctx, "error retrieving subordinate status", classified, slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, classified)
	}

	if status == nil {
		s.config().LogInfo(ctx, "subordinate status retriever returned no status and no error, treating the entity as unknown", slog.String("sub", string(*parsedSubject)))
		return s.RespondWithError(ctx, w, model.NewNotFoundError("unknown entity identifier"))
	}

	response := *status
	if response.Events == nil {
		response.Events = []model.SubordinateStatusEvent{}
	}

	statusBytes, err := json.Marshal(response)
	if err != nil {
		s.config().LogInfo(ctx, "error marshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(subordinateStatusUnavailableError))
	}

	var statusMap map[string]any
	if err = json.Unmarshal(statusBytes, &statusMap); err != nil {
		s.config().LogInfo(ctx, "error unmarshalling subordinate status response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(subordinateStatusUnavailableError))
	}
	statusMap["sub"] = *parsedSubject
	statusMap["iss"] = s.config().EntityIdentifier
	issuedAt := time.Now().UTC()
	statusMap["iat"] = issuedAt.Unix()
	if s.config().Extensions.SubordinateStatus.ResponseLifetime != nil {
		statusMap["exp"] = issuedAt.Add(*s.config().Extensions.SubordinateStatus.ResponseLifetime).Unix()
	}

	if err := model.VerifyIssuanceAlgorithm(s.config().SignerConfiguration.Algorithm); err != nil {
		s.config().LogError(ctx, "the configured signing algorithm cannot be signed with", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(subordinateStatusUnavailableError))
	}
	token, err := jwt.New(s.config().SignerConfiguration.Signer, map[string]any{
		"kid": s.config().SignerConfiguration.KeyID,
		"typ": "entity-events-statement+jwt",
		"alg": s.config().SignerConfiguration.Algorithm,
	}, statusMap, jwt.Opts{Algorithm: jwa.GetAlgorithm(s.config().SignerConfiguration.Algorithm)})
	if err != nil {
		s.config().LogInfo(ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.ClassifySignerError(err, subordinateStatusUnavailableError))
	}

	return s.RespondWithSubordinateStatementResponse(w, []byte(*token))
}
