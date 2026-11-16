package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_chain"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const resolveUnavailableError = "unable to resolve entities at this time"

func (s *Server) Resolve(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx, cancel := context.WithTimeout(r.Context(), s.config().ResolveTimeLimit())
	defer cancel()
	sub := r.URL.Query().Get("sub")
	trustAnchor := r.URL.Query().Get("trust_anchor")
	entityTypes := r.URL.Query()["entity_type"]

	s.config().LogInfo(ctx, "received resolve request", slog.String("sub", sub), slog.String("trust_anchor", trustAnchor))

	if sub == "" {
		s.config().LogInfo(ctx, "received resolve request with missing parameter 'sub'")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}
	if trustAnchor == "" {
		s.config().LogInfo(ctx, "received resolve request with missing parameter 'trust_anchor'")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("missing required parameter 'trust_anchor'"))
	}

	parsedSub, err := s.resolveEntityIdentifier(ctx, model.EntityIdentifierParamSub, sub, resolveUnavailableError)
	if err != nil {
		return s.RespondWithError(ctx, w, err)
	}

	parsedTrustAnchor, err := s.resolveEntityIdentifier(ctx, model.EntityIdentifierParamTrustAnchor, trustAnchor, resolveUnavailableError)
	if err != nil {
		return s.RespondWithError(ctx, w, err)
	}

	cache := resolvecache.New()
	cache.SetOwn(s.config().EntityIdentifier, s.ownEntityConfiguration, s.ownSubordinateStatement)

	trustChain, parsedTrustChain, _, err := trust_chain.BuildTrustChain(ctx, s.config().Configuration, *parsedSub, *parsedTrustAnchor, cache)
	if err != nil {
		return s.respondWithResolveFailure(ctx, w, "error building trust chain", err)
	}

	resolved, err := trust_chain.ResolveMetadata(ctx, s.config().Configuration, s.config().EntityIdentifier, *parsedTrustAnchor, trustChain, cache)
	if err != nil {
		return s.respondWithResolveFailure(ctx, w, "error resolving trust chain", err)
	}

	if err = trust_marks.FilterByTrusted(ctx, s.config().Configuration, resolved, parsedTrustChain[len(parsedTrustChain)-1], cache); err != nil {
		return s.respondWithResolveFailure(ctx, w, "error filtering trust marks", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		s.config().LogInfo(ctx, "the resolve request did not complete before its deadline", slog.String("error", ctxErr.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(resolveUnavailableError))
	}

	if resolved.Metadata != nil {
		resolved.Metadata.FilterByEntityTypes(entityTypes)
	}

	resolvedBytes, err := json.Marshal(resolved)
	if err != nil {
		s.config().LogError(ctx, "error marshalling resolved metadata", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(resolveUnavailableError))
	}

	var resolvedMap map[string]any
	if err = json.Unmarshal(resolvedBytes, &resolvedMap); err != nil {
		s.config().LogError(ctx, "error unmarshalling resolved metadata", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(resolveUnavailableError))
	}

	if err := model.VerifyIssuanceAlgorithm(s.config().SignerConfiguration.Algorithm); err != nil {
		s.config().LogError(ctx, "the configured signing algorithm cannot be signed with", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewServerError(resolveUnavailableError))
	}
	token, err := jwt.New(s.config().SignerConfiguration.Signer, map[string]any{
		"kid": s.config().SignerConfiguration.KeyID,
		"typ": "resolve-response+jwt",
		"alg": s.config().SignerConfiguration.Algorithm,
	}, resolvedMap, jwt.Opts{Algorithm: jwa.GetAlgorithm(s.config().SignerConfiguration.Algorithm)})
	if err != nil {
		s.config().LogError(ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.ClassifySignerError(err, resolveUnavailableError))
	}

	return s.RespondWithResolveResponse(w, []byte(*token))
}

func (s *Server) respondWithResolveFailure(ctx context.Context, w http.ResponseWriter, msg string, err error) ResponseFunc {
	s.logFailure(ctx, msg, err, slog.String("error", err.Error()))
	if _, code := errorStatusAndCode(err); code == model.ServerError {
		return s.RespondWithError(ctx, w, model.NewServerError(resolveUnavailableError))
	}
	return s.RespondWithError(ctx, w, err)
}
