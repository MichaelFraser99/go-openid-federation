package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type sentinelTransport struct {
	next     http.RoundTripper
	sentinel error
}

func (s sentinelTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "/fetch") {
		return nil, fmt.Errorf("%wrefused by policy: %s", s.sentinel, r.URL.Host)
	}
	return s.next.RoundTrip(r)
}

func TestServer_Resolve_HonoursAConsumerTransportsClassInTheResponse(t *testing.T) {
	const marker = "transport-marker"

	tests := []struct {
		name       string
		reference  string
		sentinel   error
		wantStatus int
		wantCode   string
	}{
		{name: "a transport that refuses as not found", reference: "8.1.2", sentinel: model.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: model.NotFound},
		{name: "a transport that refuses as an invalid request", reference: "8.9", sentinel: model.ErrInvalidRequest, wantStatus: http.StatusBadRequest, wantCode: model.InvalidRequest},
		{name: "a transport that refuses as an invalid subject", reference: "8.9", sentinel: model.ErrInvalidSubject, wantStatus: http.StatusNotFound, wantCode: model.InvalidSubject},
		{name: "a transport that refuses as an invalid chain", reference: "8.9", sentinel: model.ErrInvalidTrustChain, wantStatus: http.StatusBadRequest, wantCode: model.InvalidTrustChain},
		{name: "a transport that refuses as this server's own fault", reference: "8.9", sentinel: model.ErrServerError, wantStatus: http.StatusInternalServerError, wantCode: model.ServerError},
		{name: "a transport that refuses as temporarily unavailable", reference: "8.9", sentinel: model.ErrTemporarilyUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: model.TemporarilyUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer := startPeerFederation(t, func(base string) map[string]any {
				return federationFetchEndpointMetadata(base + "/" + marker + "/fetch")
			}, nil)

			signer, err := jws.GetSigner(josemodel.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the resolver signer: %v", err)
			}
			resolver := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "resolver"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
			})
			mux := http.NewServeMux()
			resolver.Configure(mux)
			resolverServer := httptest.NewTLSServer(mux)
			t.Cleanup(resolverServer.Close)
			resolver.SetEntityIdentifier(model.EntityIdentifier(resolverServer.URL))

			client := *peer.server.Client()
			client.Transport = sentinelTransport{next: peer.server.Client().Transport, sentinel: tc.sentinel}
			resolver.SetHttpClient(&client)

			response, err := resolverServer.Client().Get(resolverServer.URL + "/resolve?sub=" + peer.leafID + "&trust_anchor=" + peer.anchorID)
			if err != nil {
				t.Fatalf("the resolve handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("[%s] expected a JSON error object, got %s", tc.reference, raw)
			}

			if response.StatusCode != tc.wantStatus || body.Error != tc.wantCode {
				t.Errorf("[%s] a consumer that classifies its own transport refusal must have that class reach the caller, expected %d %q, got %d %q", tc.reference, tc.wantStatus, tc.wantCode, response.StatusCode, body.Error)
			}
			for _, absent := range []string{marker, "refused by policy"} {
				if strings.Contains(body.Description, absent) {
					t.Errorf("[%s] the peer chose that endpoint, so neither it nor the transport's text may reach the description: %q", tc.reference, body.Description)
				}
			}
		})
	}
}
