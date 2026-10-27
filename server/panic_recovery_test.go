package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type panickingRetriever struct{}

func (panickingRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	panic("the subordinate store exploded")
}

func (panickingRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	panic("the subordinate store exploded")
}

func (panickingRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	panic("the subordinate store exploded")
}

type panickingTrustMarkRetriever struct{}

func (panickingTrustMarkRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	panic("the trust mark store exploded")
}

func (panickingTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	panic("the trust mark store exploded")
}

func (panickingTrustMarkRetriever) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	panic("the trust mark store exploded")
}

func TestServer_APanickingRetrieverAnswersWithAServerError(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	server := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
		EntityConfigurationLifetime: time.Hour,
		MetadataRetriever:           panickingRetriever{},
		TrustMarkRetriever:          panickingTrustMarkRetriever{},
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	})
	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
	server.SetHttpClient(ts.Client())

	tests := []struct {
		name string
		path string
	}{
		{name: "fetch", path: "/fetch?sub=https://leaf.example.com"},
		{name: "list", path: "/list"},
		{name: "trust mark", path: "/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/a"},
		{name: "trust mark list", path: "/trust-mark-list?trust_mark_type=https://tm.example.com/a"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := ts.Client().Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("a panicking retriever dropped the connection rather than answering: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected a panicking retriever to answer 500, got %d with %s", response.StatusCode, raw)
			}

			var decoded struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("expected a JSON error response per section 8.9, got %s", raw)
			}
			if decoded.Error != model.ServerError {
				t.Errorf("expected a server_error, got %q", decoded.Error)
			}
			if decoded.Description != unexpectedFailureError {
				t.Errorf("expected the unexpected failure description, got %q", decoded.Description)
			}
		})
	}
}
