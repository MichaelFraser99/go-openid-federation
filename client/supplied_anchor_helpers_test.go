package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func resolveTrustingSuppliedAnchor(t *testing.T, c *Client, ctx context.Context, subject, trustAnchor string, chain []string) (*model.Metadata, error) {
	t.Helper()
	cfg := c.cfg
	if cfg.TrustAnchors == nil && len(chain) > 0 {
		if parts := strings.Split(chain[len(chain)-1], "."); len(parts) == 3 {
			if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var anchor struct {
					Iss  string         `json:"iss"`
					Sub  string         `json:"sub"`
					Jwks josemodel.Jwks `json:"jwks"`
				}
				if json.Unmarshal(raw, &anchor) == nil && anchor.Iss == anchor.Sub && len(anchor.Jwks.Keys) > 0 {
					cfg.TrustAnchors = map[model.EntityIdentifier]josemodel.Jwks{model.EntityIdentifier(anchor.Sub): anchor.Jwks}
				}
			}
		}
	}
	return New(cfg).ResolveMetadata(ctx, subject, trustAnchor, chain)
}
