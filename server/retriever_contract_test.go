package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type sharedStatusRetriever struct {
	shared *model.SubordinateStatusResponse
}

func (r sharedStatusRetriever) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	return r.shared, nil
}

func contractServer(t *testing.T, apply func(cfg *model.ServerConfiguration)) *httptest.Server {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	cfg := model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	}
	apply(&cfg)

	server := NewServer(cfg)
	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
	server.SetHttpClient(ts.Client())
	return ts
}

func TestServer_SubordinateStatus_DoesNotWriteIntoTheRetrieversValue(t *testing.T) {
	shared := &model.SubordinateStatusResponse{}
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.Extensions = model.Extensions{
			SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: sharedStatusRetriever{shared: shared}},
		}
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := ts.Client().Get(ts.URL + "/subordinate-status?sub=https://leaf.example.com")
			if err != nil {
				t.Errorf("the handler did not answer: %v", err)
				return
			}
			_ = response.Body.Close()
		}()
	}
	wg.Wait()

	if shared.Events != nil {
		t.Errorf("the handler wrote into the value the retriever returned, which a consumer may share or cache: %v", shared.Events)
	}
}

func TestServer_Fetch_DoesNotReflectTheRetrieversMessage(t *testing.T) {
	const secret = "connection refused: postgres://admin:hunter2@db.internal:5432"

	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.MetadataRetriever = failingSubordinateRetriever{err: errors.New(secret)}
	})

	response, err := ts.Client().Get(ts.URL + "/fetch?sub=https://leaf.example.com")
	if err != nil {
		t.Fatalf("the handler did not answer: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected a store failure to answer 500, got %d with %s", response.StatusCode, raw)
	}
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "db.internal") {
		t.Fatalf("the retriever's own message reached an unauthenticated caller: %s", raw)
	}
	if !strings.Contains(string(raw), subordinateRetrievalFailureError) {
		t.Errorf("expected the fixed description, got %s", raw)
	}
}

type perEntityFailureRetriever struct {
	err error
}

func (r perEntityFailureRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{
		{"id": "https://leaf.example.com"},
	}}, nil
}

func (r perEntityFailureRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, r.err
}

func (r perEntityFailureRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, nil
}

func (r perEntityFailureRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

func TestServer_ExtendedList_OneEntitysFaultDoesNotFailTheListing(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectStatus int
	}{
		{name: "an unknown subject is omitted", err: model.NewNotFoundError("no such subordinate"), expectStatus: http.StatusOK},
		{name: "an invalid subject is omitted", err: model.NewInvalidSubjectError("not a subject"), expectStatus: http.StatusOK},
		{name: "a store failure fails the listing", err: errors.New("the store is unreachable"), expectStatus: http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			retriever := perEntityFailureRetriever{err: tc.err}
			ts := contractServer(t, func(cfg *model.ServerConfiguration) {
				cfg.MetadataRetriever = retriever
				cfg.Extensions = model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: retriever},
				}
			})

			response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
			if err != nil {
				t.Fatalf("the handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if response.StatusCode != tc.expectStatus {
				t.Fatalf("expected status %d, got %d with %s", tc.expectStatus, response.StatusCode, raw)
			}
			if tc.expectStatus != http.StatusOK {
				return
			}

			var decoded struct {
				Entities []map[string]any `json:"immediate_subordinate_entities"`
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("expected a JSON listing, got %s", raw)
			}
			if len(decoded.Entities) != 1 {
				t.Fatalf("expected the entity to still be listed, got %s", raw)
			}
			if _, present := decoded.Entities[0]["subordinate_statement"]; present {
				t.Errorf("expected the statement to be omitted for an entity it could not be issued for, got %s", raw)
			}
		})
	}
}

type nilListingTrustMarkRetriever struct{}

func (nilListingTrustMarkRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, nil
}

func (nilListingTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, nil
}

func (nilListingTrustMarkRetriever) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, nil
}

func TestServer_TrustMarkList_AnswersAnArrayWhenNothingIsListed(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.TrustMarkRetriever = nilListingTrustMarkRetriever{}
	})

	response, err := ts.Client().Get(ts.URL + "/trust-mark-list?trust_mark_type=https://tm.example.com/a")
	if err != nil {
		t.Fatalf("the handler did not answer: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected an empty listing to answer 200, got %d with %s", response.StatusCode, raw)
	}
	if strings.TrimSpace(string(raw)) != "[]" {
		t.Errorf("[8.5.2] expected a JSON array, got %s", raw)
	}
}
