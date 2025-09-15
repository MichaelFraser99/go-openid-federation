package server

import (
	"encoding/json"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_chain"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"log/slog"
	"net/http"
	"slices"
)

//todo: consider how we can allow consumers to define their own metadata types
//todo: resolve tests

func (s *Server) Resolve(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")
	trustAnchor := r.URL.Query().Get("trust_anchor")
	entityTypes := r.URL.Query()["entity_type"]

	logging.LogInfo(s.l, ctx, "received resolve request", slog.String("sub", sub), slog.String("trust_anchor", trustAnchor))

	if sub == "" {
		logging.LogInfo(s.l, ctx, "received resolve request with missing parameter 'sub'")
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "missing 'sub' parameter"))
	}
	if trustAnchor == "" {
		logging.LogInfo(s.l, ctx, "received resolve request with missing parameter 'trust_anchor'")
		return s.RespondWithError(ctx, w, ferrors.NewError(ferrors.InvalidRequestError, "missing 'trust_anchor' parameter"))
	}

	parsedSub, err := model.ValidateEntityIdentifier(sub)
	if err != nil {
		logging.LogInfo(s.l, ctx, "invalid 'sub' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.SubjectNotFoundError())
	}

	parsedTrustAnchor, err := model.ValidateEntityIdentifier(trustAnchor)
	if err != nil {
		logging.LogInfo(s.l, ctx, "invalid 'trust_anchor' parameter", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.TrustAnchorNotFoundError())
	}

	trustChain, _, _, err := trust_chain.BuildTrustChain(ctx, s.l, s.configuration.HttpClient, *parsedSub, *parsedTrustAnchor)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error building trust chain", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	resolved, err := trust_chain.ResolveMetadata(s.configuration.EntityIdentifier, trustChain)
	if err != nil {
		logging.LogInfo(s.l, ctx, "error resolving trust chain", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
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
		logging.LogInfo(s.l, ctx, "error marshalling resolved metadata", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	var resolvedMap map[string]any
	if err = json.Unmarshal(resolvedBytes, &resolvedMap); err != nil {
		logging.LogInfo(s.l, ctx, "error unmarshalling resolved metadata", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	token, err := jwt.New(s.configuration.SignerConfiguration.Signer, map[string]any{
		"kid": s.configuration.SignerConfiguration.KeyID,
		"typ": "resolve-response+jwt",
		"alg": s.configuration.SignerConfiguration.Algorithm,
	}, resolvedMap, jwt.Opts{Algorithm: josemodel.GetAlgorithm(s.configuration.SignerConfiguration.Algorithm)})
	if err != nil {
		logging.LogInfo(s.l, ctx, "error creating resolve response", slog.String("error", err.Error()))
		return s.RespondWithError(ctx, w, ferrors.EntityNotFoundError())
	}

	return s.RespondWithResolveResponse(w, []byte(*token))
}
