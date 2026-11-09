package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const stalePage = "the pagination pointer is no longer known"

type stalePageStore struct{}

func (stalePageStore) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, model.NewPageNotFoundError(stalePage)
}

func (stalePageStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, model.NewPageNotFoundError(stalePage)
}

func (stalePageStore) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

type stalePageTrustMarks struct{}

func (stalePageTrustMarks) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, model.NewPageNotFoundError(stalePage)
}

func (stalePageTrustMarks) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, model.NewPageNotFoundError(stalePage)
}

func (stalePageTrustMarks) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, model.NewPageNotFoundError(stalePage)
}

type stalePageStatuses struct{}

func (stalePageStatuses) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	return nil, model.NewPageNotFoundError(stalePage)
}

func TestServer_PageNotFoundOutsideTheExtendedListingIsAnUnclassifiedFault(t *testing.T) {
	const subject = "https://leaf.example.com"
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		resolver    model.EntityIdentifierResolver
		description string
	}{
		{name: "the subordinate store on /fetch", path: "/fetch?sub=" + url.QueryEscape(subject), description: subordinateRetrievalFailureError},
		{name: "the subordinate store on /list", path: "/list", description: listingUnavailableError},
		{name: "the trust mark retriever on /trust-mark", path: "/trust-mark?sub=" + url.QueryEscape(subject) + "&trust_mark_type=" + url.QueryEscape("https://tm.example.com"), description: trustMarkUnavailableError},
		{name: "the trust mark retriever on /trust-mark-list", path: "/trust-mark-list?trust_mark_type=" + url.QueryEscape("https://tm.example.com"), description: trustMarkListingUnavailableError},
		{name: "the subordinate status retriever on /subordinate-status", path: "/subordinate-status?sub=" + url.QueryEscape(subject), description: subordinateStatusUnavailableError},
		{name: "the entity identifier resolver on /fetch", path: "/fetch?sub=" + url.QueryEscape(subject), resolver: failingResolver{err: model.NewPageNotFoundError(stalePage), failOn: model.EntityIdentifierParamSub}, description: subordinateStatementUnavailableError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
				MetadataRetriever:           stalePageStore{},
				TrustMarkRetriever:          stalePageTrustMarks{},
				EntityIdentifierResolver:    tc.resolver,
				Extensions: model.Extensions{
					SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: stalePageStatuses{}},
				},
			})
			mux := http.NewServeMux()
			s.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error %s: %v", raw, err)
			}
			if response.StatusCode != http.StatusInternalServerError || answer["error"] != model.ServerError || answer["error_description"] != tc.description {
				t.Errorf("[8.9] page_not_found is defined for the extended listing only, so expected 500 server_error %q, got %d %s", tc.description, response.StatusCode, raw)
			}
		})
	}
}
