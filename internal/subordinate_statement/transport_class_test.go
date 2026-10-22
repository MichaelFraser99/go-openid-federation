package subordinate_statement

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type classifyingTransport struct {
	sentinel error
}

func (c classifyingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("%wrefused by policy: %s", c.sentinel, r.URL.Host)
}

func TestRetrieve_AConsumerClassifiedTransportErrorKeepsItsClassAndNotItsText(t *testing.T) {
	const marker = "blocked-marker.example.com"

	tests := []struct {
		name      string
		reference string
		sentinel  error
	}{
		{name: "a transport that refuses as this server's own fault", reference: "8.9 server_error", sentinel: model.ErrServerError},
		{name: "a transport that refuses as an invalid chain", reference: "8.9 invalid_trust_chain", sentinel: model.ErrInvalidTrustChain},
		{name: "a transport that refuses as temporarily unavailable", reference: "8.9 temporarily_unavailable", sentinel: model.ErrTemporarilyUnavailable},
		{name: "a transport that refuses as not found", reference: "8.9 not_found", sentinel: model.ErrNotFound},
		{name: "a transport that refuses as an invalid request", reference: "8.9 invalid_request", sentinel: model.ErrInvalidRequest},
		{name: "a transport that refuses as an invalid subject", reference: "8.9 invalid_subject", sentinel: model.ErrInvalidSubject},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey(t)
			issuer := model.EntityStatement{
				Iss:      "https://ta.example.com",
				Sub:      "https://ta.example.com",
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": "https://" + marker + "/fetch"}},
				JWKs:     josemodel.Jwks{Keys: []map[string]any{testPublicJwk(t, key.Public(), "ta")}},
			}

			cfg := model.Configuration{HttpClient: &http.Client{Transport: classifyingTransport{sentinel: tc.sentinel}}}

			_, _, err := Retrieve(t.Context(), cfg, issuer, "https://leaf.example.com")
			if err == nil {
				t.Fatalf("[%s] expected the refusal to be reported", tc.reference)
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("[%s] a consumer that classifies its own transport refusal must have that class honoured, got %v", tc.reference, err)
			}
			for _, absent := range []string{marker, "refused by policy"} {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("[%s] the peer chose that endpoint, so neither it nor the transport's text may reach the description: %v", tc.reference, err)
				}
			}
		})
	}
}
