package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_ASubordinateAddedInMemoryIsServedForAsLongAsItIsListed(t *testing.T) {
	tests := []struct {
		name      string
		cacheTime time.Duration
	}{
		{name: "the zero value", cacheTime: 0},
		{name: "a cache time that has passed", cacheTime: time.Nanosecond},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			publicJWK, err := jwk.PublicJwk(signer.Public())
			if err != nil {
				t.Fatalf("failed to build the public jwk: %v", err)
			}
			intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: tc.cacheTime}
			intermediate.AddSubordinate("https://leaf.example.com", leafSubordinate(t))
			ts := startFetchServer(t, model.ServerConfiguration{
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: (*publicJWK)["kid"].(string)},
				IntermediateConfiguration: intermediate,
			})
			time.Sleep(time.Millisecond)

			listed := get(t, ts, "/list")
			body, err := io.ReadAll(listed.Body)
			_ = listed.Body.Close()
			if err != nil {
				t.Fatalf("failed to read the listing: %v", err)
			}
			if !strings.Contains(string(body), "https://leaf.example.com") {
				t.Fatalf("the fixture is wrong: the subordinate is not listed, got %s", body)
			}

			fetched := get(t, ts, "/fetch?sub="+url.QueryEscape("https://leaf.example.com"))
			_ = fetched.Body.Close()
			if fetched.StatusCode != http.StatusOK {
				t.Errorf("[8.1.1] a subordinate this server lists must be fetchable, got %d", fetched.StatusCode)
			}
		})
	}
}
