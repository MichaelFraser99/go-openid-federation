package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type shapedExtendedRetriever struct {
	entities []map[string]any
}

func (r shapedExtendedRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return &model.ExtendedListingResponse{ImmediateSubordinateEntities: r.entities}, nil
}

func TestServer_ExtendedList_MalformedEntityIdentifier(t *testing.T) {
	tests := []struct {
		name         string
		entities     []map[string]any
		expectStatus int
		expectError  string
		expectDesc   string
	}{
		{
			name:         "an id that is a number",
			entities:     []map[string]any{{"id": 7}},
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
		},
		{
			name:         "an id that is a float, as a JSON round trip produces",
			entities:     []map[string]any{{"id": float64(7)}},
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
		},
		{
			name:         "an id that is an object",
			entities:     []map[string]any{{"id": map[string]any{}}},
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
		},
		{
			name:         "a string id that is not an entity identifier",
			entities:     []map[string]any{{"id": "not-an-entity-identifier"}},
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
			expectDesc:   extendedListingUnavailableError,
		},
		{
			name:         "a string id over plain http",
			entities:     []map[string]any{{"id": "http://leaf.example.com"}},
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
			expectDesc:   extendedListingUnavailableError,
		},
		{
			name:         "an absent id",
			entities:     []map[string]any{{"other": "value"}},
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(josemodel.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}

			server := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: shapedExtendedRetriever{entities: tc.entities}},
				},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewTLSServer(mux)
			defer ts.Close()
			server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
			server.SetHttpClient(ts.Client())

			response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
			if err != nil {
				t.Fatalf("the handler did not answer, which is what a panic looks like to a caller: %v", err)
			}
			desc := tc.expectDesc
			if desc == "" {
				desc = extendedListingMalformedIdentifierError
			}
			validateErrorResponse(t, response, nil, tc.expectStatus, tc.expectError, desc)
		})
	}
}
