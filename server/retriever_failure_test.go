package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type failingSubordinateRetriever struct {
	err error
}

func (r failingSubordinateRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, r.err
}

func (r failingSubordinateRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, r.err
}

func (r failingSubordinateRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

func TestServer_Fetch_DistinguishesAStoreFailureFromAnUnknownSubject(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectStatus int
		expectError  string
	}{
		{
			name:         "an unknown subject is not found",
			err:          model.NewNotFoundError("no such subordinate"),
			expectStatus: http.StatusNotFound,
			expectError:  "not_found",
		},
		{
			name:         "a store failure is a server error",
			err:          errors.New("the subordinate store is unreachable"),
			expectStatus: http.StatusInternalServerError,
			expectError:  "server_error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}

			server := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
				EntityConfigurationLifetime: time.Hour,
				MetadataRetriever:           failingSubordinateRetriever{err: tc.err},
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewTLSServer(mux)
			defer ts.Close()
			server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
			server.SetHttpClient(ts.Client())

			response, err := ts.Client().Get(ts.URL + "/fetch?sub=https://leaf.example.com")
			if err != nil {
				t.Fatalf("the handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			if response.StatusCode != tc.expectStatus {
				t.Fatalf("expected status %d, got %d", tc.expectStatus, response.StatusCode)
			}
		})
	}
}
