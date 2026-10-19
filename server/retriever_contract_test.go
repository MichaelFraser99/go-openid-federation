package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestServer_ExtendedList_EntitySpecificFaultsAreOmittedAndOthersFail(t *testing.T) {
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

type leakingTrustMarkRetriever struct {
	err error
}

func (r leakingTrustMarkRetriever) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, r.err
}

func (r leakingTrustMarkRetriever) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, r.err
}

func (r leakingTrustMarkRetriever) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, r.err
}

func TestServer_TrustMarkEndpoints_DoNotReflectTheRetrieversMessage(t *testing.T) {
	const secret = "dial tcp db.internal:5432: connect: connection refused for user admin"

	tests := []struct {
		name   string
		method string
		path   string
		form   url.Values
	}{
		{name: "trust mark", method: http.MethodGet, path: "/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/a"},
		{name: "trust mark list", method: http.MethodGet, path: "/trust-mark-list?trust_mark_type=https://tm.example.com/a"},
		{name: "trust mark status", method: http.MethodPost, path: "/trust-mark-status", form: url.Values{"trust_mark": {"a.b.c"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := contractServer(t, func(cfg *model.ServerConfiguration) {
				cfg.TrustMarkRetriever = leakingTrustMarkRetriever{err: errors.New(secret)}
			})

			var body io.Reader
			if tc.form != nil {
				body = strings.NewReader(tc.form.Encode())
			}
			request, err := http.NewRequest(tc.method, ts.URL+tc.path, body)
			if err != nil {
				t.Fatalf("failed to build the request: %v", err)
			}
			if tc.form != nil {
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			response, err := ts.Client().Do(request)
			if err != nil {
				t.Fatalf("the handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected an unclassified retriever error to answer 500, got %d with %s", response.StatusCode, raw)
			}
			if strings.Contains(string(raw), "db.internal") || strings.Contains(string(raw), "admin") {
				t.Fatalf("the retriever's own message reached an unauthenticated caller: %s", raw)
			}
		})
	}
}

func TestServer_TrustMarkEndpoints_PassAClassifiedErrorThrough(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.TrustMarkRetriever = leakingTrustMarkRetriever{err: model.NewUnsupportedParameterError("trust mark issuance not supported")}
	})

	response, err := ts.Client().Get(ts.URL + "/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/a")
	if err != nil {
		t.Fatalf("the handler did not answer: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}
	if !strings.Contains(string(raw), "unsupported_parameter") {
		t.Fatalf("expected a classified retriever error to choose what the peer sees, got %s", raw)
	}
}

type leakingEverythingRetriever struct {
	err error
}

func (r leakingEverythingRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, r.err
}

func (r leakingEverythingRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, r.err
}

func (r leakingEverythingRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, r.err
}

func (r leakingEverythingRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return nil, r.err
}

func (r leakingEverythingRetriever) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	return nil, r.err
}

func TestServer_NoEndpointReflectsTheRetrieversMessage(t *testing.T) {
	const secret = "dial tcp db.internal:5432: connect: refused for user admin password hunter2"

	retriever := leakingEverythingRetriever{err: errors.New(secret)}
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.MetadataRetriever = retriever
		cfg.TrustMarkRetriever = leakingTrustMarkRetriever{err: errors.New(secret)}
		cfg.Extensions = model.Extensions{
			ExtendedListing:   model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: retriever},
			SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: retriever},
		}
	})

	paths := []string{
		"/.well-known/openid-federation",
		"/list",
		"/list?entity_type=openid_relying_party",
		"/fetch?sub=https://leaf.example.com",
		"/extended-list",
		"/extended-list?claims=subordinate_statement",
		"/subordinate-status?sub=https://leaf.example.com",
		"/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/a",
		"/trust-mark-list?trust_mark_type=https://tm.example.com/a",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			response, err := ts.Client().Get(ts.URL + path)
			if err != nil {
				t.Fatalf("the handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			for _, fragment := range []string{"db.internal", "hunter2", "admin", "dial tcp"} {
				if strings.Contains(string(raw), fragment) {
					t.Fatalf("the retriever's own message reached an unauthenticated caller: %s", raw)
				}
			}
		})
	}
}

type panickingLogHandler struct{}

func (panickingLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (panickingLogHandler) Handle(context.Context, slog.Record) error {
	panic("the log sink exploded")
}

func (h panickingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h panickingLogHandler) WithGroup(string) slog.Handler { return h }

func TestServer_APanicInTheRecoveryPathStillAnswers(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.MetadataRetriever = panickingRetriever{}
		cfg.Logger = slog.New(panickingLogHandler{})
	})

	response, err := ts.Client().Get(ts.URL + "/fetch?sub=https://leaf.example.com")
	if err != nil {
		t.Fatalf("a panic inside the recovery path dropped the connection, which is the failure recovery exists to remove: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.StatusCode)
	}
}
