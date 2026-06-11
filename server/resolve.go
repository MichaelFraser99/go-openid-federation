package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"

	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_chain"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_marks"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const resolveUnavailableError = "unable to resolve entities at this time"

//todo: consider how we can allow consumers to define their own metadata types
//todo: resolve tests

func (s *Server) Resolve(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustAnchor := r.URL.Query().Get("trust_anchor")
	entityTypes := r.URL.Query()["entity_type"]

	s.cfg.LogInfo(ctx, "received resolve request", slog.String("sub", sub), slog.String("trust_anchor", trustAnchor))

	if sub == "" {
		s.cfg.LogInfo(ctx, "received resolve request with missing parameter 'sub'")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}
	if trustAnchor == "" {
		s.cfg.LogInfo(ctx, "received resolve request with missing parameter 'trust_anchor'")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("missing required parameter 'trust_anchor'"))
	}

	parsedSub, err := model.ValidateEntityIdentifier(sub)
	if err != nil {
		s.cfg.LogInfo(ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'sub' parameter"))
	}

	parsedTrustAnchor, err := model.ValidateEntityIdentifier(trustAnchor)
	if err != nil {
		s.cfg.LogInfo(ctx, "invalid 'trust_anchor' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("malformed 'trust_anchor' parameter"))
	}

	trustChain, parsedTrustChain, _, err := trust_chain.BuildTrustChain(ctx, s.cfg.Configuration, *parsedSub, *parsedTrustAnchor)
	if err != nil {
		s.cfg.LogInfo(ctx, "error building trust chain", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	resolved, err := trust_chain.ResolveMetadata(ctx, s.cfg.Configuration, s.cfg.EntityIdentifier, trustChain)
	if err != nil {
		s.cfg.LogInfo(ctx, "error resolving trust chain", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	if err = trust_marks.FilterByTrusted(ctx, s.cfg.Configuration, resolved, parsedTrustChain[len(parsedTrustChain)-1]); err != nil {
		s.cfg.LogInfo(ctx, "error filtering trust marks", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, err)
	}

	if len(entityTypes) > 0 {
		if !slices.Contains(entityTypes, "federation_entity") {
			resolved.Metadata.FederationMetadata = nil
		}
		if !slices.Contains(entityTypes, "openid_provider") {
			resolved.Metadata.OpenIDConnectOpenIDProviderMetadata = nil
		}
		if !slices.Contains(entityTypes, "openid_relying_party") {
			resolved.Metadata.OpenIDRelyingPartyMetadata = nil
		}
	}

	resolvedBytes, err := json.Marshal(resolved)
	if err != nil {
		s.cfg.LogError(ctx, "error marshalling resolved metadata", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(resolveUnavailableError))
	}

	var resolvedMap map[string]any
	if err = json.Unmarshal(resolvedBytes, &resolvedMap); err != nil {
		s.cfg.LogError(ctx, "error unmarshalling resolved metadata", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(resolveUnavailableError))
	}

	token, err := jwt.New(s.cfg.SignerConfiguration.Signer, map[string]any{
		"kid": s.cfg.SignerConfiguration.KeyID,
		"typ": "resolve-response+jwt",
		"alg": s.cfg.SignerConfiguration.Algorithm,
	}, resolvedMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(s.cfg.SignerConfiguration.Algorithm)})
	if err != nil {
		s.cfg.LogError(ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, model.NewTemporarilyUnavailableError(resolveUnavailableError))
	}

	return s.RespondWithResolveResponse(w, []byte(*token))
}
