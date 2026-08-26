package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

// mappingResolver maps chosen raw values onto real identifiers, delegating to the
// standard resolver for final validation, and records which parameters it saw.
type mappingResolver struct {
	mappings map[string]string
	errOn    string
	seen     []model.EntityIdentifierParam
}

func (r *mappingResolver) ResolveEntityIdentifier(ctx context.Context, param model.EntityIdentifierParam, raw string) (*model.EntityIdentifier, error) {
	r.seen = append(r.seen, param)
	if raw == r.errOn {
		return nil, model.NewNotFoundError("unknown alias")
	}
	if mapped, ok := r.mappings[raw]; ok {
		raw = mapped
	}
	return model.StandardEntityIdentifierResolver{}.ResolveEntityIdentifier(ctx, param, raw)
}

func TestServer_Fetch_EntityIdentifierResolver(t *testing.T) {
	const realSubordinate = "https://some-federation.com/some-path"

	subordinateSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating subordinate signer, got %q", err.Error())
	}
	subordinateJWK, err := jwk.PublicJwk(subordinateSigner.Public())
	if err != nil {
		t.Fatalf("expected no error creating subordinate JWK, got %q", err.Error())
	}

	tests := map[string]struct {
		resolver   *mappingResolver
		requestSub string
		validate   func(t *testing.T, resolver *mappingResolver, response *http.Response)
	}{
		"custom resolver maps a non-standard sub to the real subordinate": {
			resolver:   &mappingResolver{mappings: map[string]string{"alias-123": realSubordinate}},
			requestSub: "alias-123",
			validate: func(t *testing.T, resolver *mappingResolver, response *http.Response) {
				assertStatus(t, response, http.StatusOK)
				if len(resolver.seen) == 0 || resolver.seen[0] != model.EntityIdentifierParamSub {
					t.Errorf("resolver saw params %v, want first to be %q", resolver.seen, model.EntityIdentifierParamSub)
				}
			},
		},
		"an unmapped standard sub passes through unchanged": {
			resolver:   &mappingResolver{mappings: map[string]string{}},
			requestSub: realSubordinate,
			validate: func(t *testing.T, _ *mappingResolver, response *http.Response) {
				assertStatus(t, response, http.StatusOK)
			},
		},
		"a resolver error surfaces with its own status": {
			resolver:   &mappingResolver{errOn: "bad-alias"},
			requestSub: "bad-alias",
			validate: func(t *testing.T, _ *mappingResolver, response *http.Response) {
				validateErrorResponse(t, response, nil, http.StatusNotFound, "not_found", "unknown alias")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSigner(josemodel.ES256, nil)
			if err != nil {
				t.Fatalf("expected no error creating signer, got %q", err.Error())
			}
			signerPublicJWK, err := jwk.PublicJwk(signer.Public())
			if err != nil {
				t.Fatalf("expected no error creating public JWK, got %q", err.Error())
			}

			intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
			intermediate.AddSubordinate(realSubordinate, &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{*subordinateJWK}},
			})

			serverConfig := model.ServerConfiguration{
				SignerConfiguration: model.SignerConfiguration{
					Algorithm: "ES256",
					Signer:    signer,
					KeyID:     (*signerPublicJWK)["kid"].(string),
				},
				EntityIdentifier:          "https://some-trust-anchor.com/",
				IntermediateConfiguration: intermediate,
				EntityConfiguration:       model.EntityStatement{Iss: "https://some-trust-anchor.com/"},
				EntityIdentifierResolver:  tt.resolver,
				Configuration: model.Configuration{
					Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
				},
			}

			server := NewServer(serverConfig)
			m := http.NewServeMux()
			server.Configure(m)
			s := httptest.NewServer(m)
			defer s.Close()

			requestURL := fmt.Sprintf("%s/fetch?sub=%s", s.URL, url.QueryEscape(tt.requestSub))
			resp, err := s.Client().Get(requestURL)
			if err != nil {
				t.Fatalf("expected no error issuing request, got %q", err.Error())
			}
			tt.validate(t, tt.resolver, resp)
		})
	}
}

func assertStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response == nil {
		t.Fatal("expected a response, got nil")
	}
	defer response.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("status = %d, want %d (body: %s)", response.StatusCode, want, body)
	}
}
