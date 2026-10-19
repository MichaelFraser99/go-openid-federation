package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type nilSubordinateRetriever struct{}

func (nilSubordinateRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, nil
}

func (nilSubordinateRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return map[model.EntityIdentifier]*model.SubordinateConfiguration{"https://leaf.example.com": nil}, nil
}

func (nilSubordinateRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

type nilSubordinateStatusRetriever struct{}

func (nilSubordinateStatusRetriever) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	return nil, nil
}

type nilTrustMarkRetriever struct{}

func (nilTrustMarkRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, nil
}

func (nilTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, nil
}

func (nilTrustMarkRetriever) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, nil
}

func nilRetrieverServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build the public jwk: %v", err)
	}
	(*publicJWK)["kid"] = "server"

	server := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
		EntityConfigurationLifetime: time.Hour,
		MetadataRetriever:           nilSubordinateRetriever{},
		TrustMarkRetriever:          nilTrustMarkRetriever{},
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
		Extensions: model.Extensions{
			SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: nilSubordinateStatusRetriever{}},
		},
	})

	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
	server.SetHttpClient(ts.Client())
	return ts, server
}

func TestServer_RetrieverReturningNilWithoutError(t *testing.T) {
	ts, _ := nilRetrieverServer(t)

	tests := []struct {
		name         string
		reference    string
		path         string
		expectStatus int
		expectError  string
		expectDesc   string
	}{
		{
			name:         "fetch reports the subject as not found",
			reference:    "8.1.2",
			path:         "/fetch?sub=https://leaf.example.com",
			expectStatus: http.StatusNotFound,
			expectError:  "not_found",
			expectDesc:   "unknown entity identifier",
		},
		{
			name:         "subordinate status reports the subject as not found",
			reference:    "Subordinate Status extension",
			path:         "/subordinate-status?sub=https://leaf.example.com",
			expectStatus: http.StatusNotFound,
			expectError:  "not_found",
			expectDesc:   "unknown entity identifier",
		},
		{
			name:         "trust mark reports the entity as not holding it",
			reference:    "8.6.2",
			path:         "/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/a",
			expectStatus: http.StatusNotFound,
			expectError:  "not_found",
			expectDesc:   "entity does not have the specified trust mark",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := ts.Client().Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("[%s] the handler did not answer, which is what a panic looks like to a caller: %v", tc.reference, err)
			}
			validateErrorResponse(t, response, nil, tc.expectStatus, tc.expectError, tc.expectDesc)
		})
	}
}
