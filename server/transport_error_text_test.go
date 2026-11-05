package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type refusingTransport struct {
	next   http.RoundTripper
	refuse string
	err    error
}

func (r refusingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.Contains(request.URL.String(), r.refuse) {
		return nil, r.err
	}
	return r.next.RoundTrip(request)
}

func TestServer_Resolve_ATransportErrorDoesNotCarryAPeersURLIntoTheResponse(t *testing.T) {
	const marker = "peer-chosen-9Kx"

	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "a transport refusal this server classes as its own fault", err: fmt.Errorf("%w: refused by egress policy", model.ErrServerError), status: http.StatusInternalServerError, code: model.ServerError},
		{name: "an unclassified transport failure", err: fmt.Errorf("dial refused"), status: http.StatusNotFound, code: model.InvalidTrustAnchor},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the leaf signer: %v", err)
			}
			hint := model.EntityIdentifier("https://superior.example.com/" + marker)
			leaf := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: leafSigner, KeyID: "leaf"},
				EntityConfigurationLifetime: 10 * time.Minute,
				AuthorityHints:              []model.EntityIdentifier{hint},
			})
			leafMux := http.NewServeMux()
			leaf.Configure(leafMux)
			leafServer := httptest.NewTLSServer(leafMux)
			t.Cleanup(leafServer.Close)
			leaf.SetEntityIdentifier(model.EntityIdentifier(leafServer.URL))

			resolverSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the resolver signer: %v", err)
			}
			resolver := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: resolverSigner, KeyID: "resolver"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{},
			})
			resolverMux := http.NewServeMux()
			resolver.Configure(resolverMux)
			resolverServer := httptest.NewServer(resolverMux)
			t.Cleanup(resolverServer.Close)
			resolver.SetEntityIdentifier("https://resolver.example.com")
			resolver.SetHttpClient(&http.Client{Transport: refusingTransport{next: leafServer.Client().Transport, refuse: marker, err: tc.err}})

			response, err := http.Get(resolverServer.URL + "/resolve?sub=" + url.QueryEscape(leafServer.URL) + "&trust_anchor=" + url.QueryEscape(string(hint)))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("[8.9] expected %d, got %d %s", tc.status, response.StatusCode, raw)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if answer["error"] != tc.code {
				t.Errorf("[8.9] expected %s, got %s", tc.code, raw)
			}
			if strings.Contains(answer["error_description"], marker) || strings.Contains(answer["error_description"], "superior.example.com/") {
				t.Errorf("[8.9] a URL a peer published must not reach the description, got %q", answer["error_description"])
			}
		})
	}
}
