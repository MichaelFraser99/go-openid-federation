package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_APeerThatDidNotAnswerGetsTheSameResponseAsOneThatAnswered404(t *testing.T) {
	peers := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang/.well-known/openid-federation" {
			<-r.Context().Done()
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(peers.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve an address: %v", err)
	}
	closed := "https://" + listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatalf("failed to release the address: %v", err)
	}

	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the resolver signer: %v", err)
	}
	resolver := mustNewServer(t, model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "resolver"},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
		Configuration:               model.Configuration{MaxPeerResponseTime: 300 * time.Millisecond},
	})
	mux := http.NewServeMux()
	resolver.Configure(mux)
	resolverServer := httptest.NewTLSServer(mux)
	t.Cleanup(resolverServer.Close)
	resolver.SetEntityIdentifier(model.EntityIdentifier(resolverServer.URL))
	resolver.SetHttpClient(peers.Client())

	for name, subject := range map[string]string{
		"a subject that answers 404":                           peers.URL + "/missing",
		"a subject that cannot be reached":                     closed + "/missing",
		"a subject that does not answer within the peer bound": peers.URL + "/hang",
	} {
		t.Run(name, func(t *testing.T) {
			response, err := resolverServer.Client().Get(resolverServer.URL + "/resolve?sub=" + url.QueryEscape(subject) + "&trust_anchor=" + url.QueryEscape(peers.URL+"/ta"))
			if err != nil {
				t.Fatalf("the resolve handler did not answer: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			var body map[string]any
			if err = json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("expected a JSON error response, got %s", raw)
			}
			if response.StatusCode != http.StatusNotFound || body["error"] != model.NotFound || body["error_description"] != "failed to retrieve entity configuration for "+subject {
				t.Errorf("[8.9] the client markers change no wire error, expected 404 not_found naming the subject, got %d with %s", response.StatusCode, raw)
			}
		})
	}
}
