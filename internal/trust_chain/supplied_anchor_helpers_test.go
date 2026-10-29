package trust_chain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func withAnchorKeysFrom(t *testing.T, cfg model.Configuration, chain []string) model.Configuration {
	t.Helper()
	if cfg.TrustAnchors != nil || len(chain) == 0 {
		return cfg
	}
	parts := strings.Split(chain[len(chain)-1], ".")
	if len(parts) != 3 {
		return cfg
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cfg
	}
	var anchor struct {
		Iss  string         `json:"iss"`
		Sub  string         `json:"sub"`
		Jwks josemodel.Jwks `json:"jwks"`
	}
	if json.Unmarshal(raw, &anchor) != nil || anchor.Iss != anchor.Sub || len(anchor.Jwks.Keys) == 0 {
		return cfg
	}
	cfg.TrustAnchors = map[model.EntityIdentifier]josemodel.Jwks{model.EntityIdentifier(anchor.Sub): anchor.Jwks}
	return cfg
}

func resolveTrustingSuppliedAnchor(t *testing.T, ctx context.Context, cfg model.Configuration, issuer, trustAnchor model.EntityIdentifier, chain []string, cache *resolvecache.Cache) (*model.ResolveResponse, error) {
	t.Helper()
	return ResolveMetadata(ctx, withAnchorKeysFrom(t, cfg, chain), issuer, trustAnchor, chain, cache)
}
