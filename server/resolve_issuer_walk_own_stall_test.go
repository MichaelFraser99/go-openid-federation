package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/internal/truncate"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type stallingIssuerStore struct {
	issuer        *atomic.Value
	issuerKeys    josemodel.Jwks
	stallIssuance *atomic.Bool
	stallSigners  *atomic.Bool
}

func (s stallingIssuerStore) GetSubordinate(ctx context.Context, identifier model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	if s.stallIssuance.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if identifier != s.issuer.Load() {
		return nil, model.NewNotFoundError("unknown entity identifier")
	}
	return &model.SubordinateConfiguration{JWKs: s.issuerKeys}, nil
}

func (s stallingIssuerStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return map[model.EntityIdentifier]*model.SubordinateConfiguration{s.issuer.Load().(model.EntityIdentifier): {JWKs: s.issuerKeys}}, nil
}

func (s stallingIssuerStore) GetSubordinateSigners(ctx context.Context) ([]model.SignerConfiguration, error) {
	if s.stallSigners.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, nil
}

func TestServer_Resolve_ThisServersOwnWorkStalledInATrustMarkIssuerWalkIsTemporarilyUnavailable(t *testing.T) {
	tests := []struct {
		name          string
		stallIssuance bool
		stallSigners  bool
		status        int
		code          string
		description   string
	}{
		{
			name:   "this server answers for its subordinate within the deadline",
			status: http.StatusOK,
		},
		{
			name:          "this server's store stalls while it issues its statement about the trust mark issuer",
			stallIssuance: true,
			status:        http.StatusServiceUnavailable,
			code:          model.TemporarilyUnavailable,
			description:   "unable to produce the subordinate statement at this time",
		},
		{
			name:         "this server's store stalls while it builds its own entity configuration for the trust mark issuer's walk",
			stallSigners: true,
			status:       http.StatusServiceUnavailable,
			code:         model.TemporarilyUnavailable,
			description:  "unable to produce the entity configuration at this time",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			federationSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the federation signer: %v", err)
			}
			federationJWK, err := jwk.PublicJwk(federationSigner.Public())
			if err != nil {
				t.Fatalf("failed to read the federation key: %v", err)
			}
			(*federationJWK)["kid"] = "federation"
			resolverSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the resolver signer: %v", err)
			}
			resolverJWK, err := jwk.PublicJwk(resolverSigner.Public())
			if err != nil {
				t.Fatalf("failed to read the resolver key: %v", err)
			}
			(*resolverJWK)["kid"] = "resolver"

			sign := func(typ string, body map[string]any) string {
				token, err := jwt.New(federationSigner, map[string]any{"kid": "federation", "typ": typ, "alg": "ES256"}, body, jwt.Opts{Algorithm: jwa.ES256})
				if err != nil {
					t.Errorf("failed to sign a federation token: %v", err)
					return ""
				}
				return *token
			}

			var base, resolverURL string
			federation := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				name, wellKnown := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
				leaf, anchor, issuer := base+"/leaf", base+"/ta", base+"/issuer"
				now := time.Now().UTC()
				statement := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": map[string]any{"keys": []any{*federationJWK}}}
				switch {
				case wellKnown && name == "leaf":
					statement["iss"], statement["sub"], statement["authority_hints"] = leaf, leaf, []any{anchor}
					statement["trust_marks"] = []any{map[string]any{
						"trust_mark_type": deadlineTrustMarkType,
						"trust_mark": sign("trust-mark+jwt", map[string]any{
							"iss": issuer, "sub": leaf, "trust_mark_type": deadlineTrustMarkType, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
						}),
					}}
				case wellKnown && name == "issuer":
					statement["iss"], statement["sub"], statement["authority_hints"] = issuer, issuer, []any{resolverURL}
				case wellKnown && name == "ta":
					statement["iss"], statement["sub"] = anchor, anchor
					statement["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": anchor + "/fetch"}}
					statement["trust_mark_issuers"] = map[string]any{deadlineTrustMarkType: []any{issuer}}
				case r.URL.Path == "/ta/fetch":
					statement["iss"], statement["sub"] = anchor, r.URL.Query().Get("sub")
					if r.URL.Query().Get("sub") == resolverURL {
						statement["jwks"] = map[string]any{"keys": []any{*resolverJWK}}
					}
				default:
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(sign("entity-statement+jwt", statement)))
			}))
			t.Cleanup(federation.Close)
			base = federation.URL

			issuer := &atomic.Value{}
			issuer.Store(model.EntityIdentifier(base + "/issuer"))
			store := stallingIssuerStore{
				issuer:        issuer,
				issuerKeys:    josemodel.Jwks{Keys: []map[string]any{*federationJWK}},
				stallIssuance: &atomic.Bool{},
				stallSigners:  &atomic.Bool{},
			}
			resolveTime := 10 * time.Second
			if tc.stallIssuance || tc.stallSigners {
				resolveTime = 300 * time.Millisecond
			}
			resolver := mustNewServer(t, model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: resolverSigner, KeyID: "resolver"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
				MetadataRetriever:           store,
				Configuration:               model.Configuration{MaxResolveTime: resolveTime, MaxPeerResponseTime: 10 * time.Second},
			})
			mux := http.NewServeMux()
			resolver.Configure(mux)
			resolverServer := httptest.NewTLSServer(mux)
			t.Cleanup(resolverServer.Close)
			resolverURL = resolverServer.URL
			resolver.SetEntityIdentifier(model.EntityIdentifier(resolverURL))
			resolver.SetHttpClient(federation.Client())
			if err := resolver.AddAuthorityHint(model.EntityIdentifier(base + "/ta")); err != nil {
				t.Fatalf("failed to add the resolver's authority hint: %v", err)
			}
			store.stallIssuance.Store(tc.stallIssuance)
			store.stallSigners.Store(tc.stallSigners)

			response, err := resolverServer.Client().Get(resolverServer.URL + "/resolve?sub=" + base + "/leaf&trust_anchor=" + base + "/ta")
			if err != nil {
				t.Fatalf("the resolve handler did not answer: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if response.StatusCode != tc.status {
				t.Fatalf("[8.9] expected %d, got %d with %s", tc.status, response.StatusCode, truncate.TruncateForResponse(string(raw)))
			}
			if tc.code == "" {
				if marks := resolveResponseTrustMarks(t, raw); len(marks) != 1 {
					t.Errorf("[8.3.2] the fixture is wrong: expected the trust mark verified through this server, got %v", marks)
				}
				return
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("expected a JSON error response, got %s", truncate.TruncateForResponse(string(raw)))
			}
			if body["error"] != tc.code {
				t.Errorf("[8.9] the time went to this server's own store, which no peer chose, so the request did not complete, temporarily_unavailable, got %s", truncate.TruncateForResponse(string(raw)))
			}
			if body["error_description"] != tc.description {
				t.Errorf("[8.9] expected the description to name which of this server's own statements did not complete, %q, got %v", tc.description, body["error_description"])
			}
		})
	}
}
