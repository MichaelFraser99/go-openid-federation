package server

import (
	"fmt"
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

func cacheTestSigner(t *testing.T) (model.SignerConfiguration, map[string]any) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: (*pub)["kid"].(string)}, *pub
}

func cacheTestServer(t *testing.T, ic *model.IntermediateConfiguration, retriever model.Retriever) *Server {
	t.Helper()
	signer, _ := cacheTestSigner(t)
	return NewServer(model.ServerConfiguration{
		SignerConfiguration:         signer,
		EntityIdentifier:            "https://ta.example.com",
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   ic,
		MetadataRetriever:           retriever,
	})
}

func TestServer_StaticSubordinatesCanChangeWhileServing(t *testing.T) {
	_, pub := cacheTestSigner(t)
	pub["kid"] = "sub"
	ic := &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute, SubordinateCacheTime: time.Hour}
	s := cacheTestServer(t, ic, nil)
	mux := http.NewServeMux()
	s.Configure(mux)
	var wg sync.WaitGroup
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch i % 5 {
			case 0:
				ic.AddSubordinate(model.EntityIdentifier(fmt.Sprintf("https://sub%d.example.com", i)), &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{pub}}})
			case 1:
				ic.FlushCache()
			case 2:
				mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/list", nil))
			case 3:
				mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation", nil))
			case 4:
				mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, fmt.Sprintf("/fetch?sub=https://sub%d.example.com", i-4), nil))
			}
		}()
	}
	wg.Wait()
}
