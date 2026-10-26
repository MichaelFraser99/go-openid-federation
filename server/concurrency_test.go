package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type concurrentRetriever struct {
	jwks josemodel.Jwks
}

func (r concurrentRetriever) GetSubordinate(_ context.Context, identifier model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return &model.SubordinateConfiguration{JWKs: r.jwks}, nil
}

func (r concurrentRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return map[model.EntityIdentifier]*model.SubordinateConfiguration{}, nil
}

func (r concurrentRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

func concurrencyServer(t *testing.T) *Server {
	t.Helper()

	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to create public jwk: %v", err)
	}
	(*publicJWK)["alg"] = "ES256"

	subjectSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to create subject signer: %v", err)
	}
	subjectJWK, err := jwk.PublicJwk(subjectSigner.Public())
	if err != nil {
		t.Fatalf("failed to create subject public jwk: %v", err)
	}
	(*subjectJWK)["alg"] = "ES256"

	return NewServer(model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		EntityConfigurationLifetime: time.Hour,
		SignerConfiguration: model.SignerConfiguration{
			KeyID:     (*publicJWK)["kid"].(string),
			Algorithm: "ES256",
			Signer:    signer,
		},
		EntityConfiguration: model.EntityStatement{
			Metadata: &model.Metadata{
				FederationMetadata: &model.FederationMetadata{"organization_name": "Example"},
			},
		},
		IntermediateConfiguration: &model.IntermediateConfiguration{
			SubordinateStatementLifetime: time.Hour,
		},
		MetadataRetriever: concurrentRetriever{jwks: josemodel.Jwks{Keys: []map[string]any{*subjectJWK}}},
	})
}

func TestServer_ConcurrentRequestsDoNotRaceOnSharedState(t *testing.T) {
	s := concurrencyServer(t)
	mux := http.NewServeMux()
	s.Configure(mux)

	const workers = 60
	var wg sync.WaitGroup

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			wellKnown := httptest.NewRecorder()
			mux.ServeHTTP(wellKnown, httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation", nil))
			if wellKnown.Code != http.StatusOK {
				t.Errorf("well-known request returned %d", wellKnown.Code)
			}

			fetch := httptest.NewRecorder()
			mux.ServeHTTP(fetch, httptest.NewRequest(http.MethodGet, "/fetch?sub=https://leaf.example.com", nil))
			if fetch.Code != http.StatusOK {
				t.Errorf("fetch request returned %d: %s", fetch.Code, fetch.Body.String())
			}

			if i%4 == 0 {
				s.AddAuthorityHint(model.EntityIdentifier("https://authority.example.com"))
			}
		}(i)
	}

	wg.Wait()
}
