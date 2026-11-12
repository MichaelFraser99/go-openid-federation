package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const retrieverLeak = "dial tcp 10.0.0.7:5432 as federation_admin"

type failingStore struct{ err error }

func (s failingStore) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, s.err
}

func (s failingStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, s.err
}

func (failingStore) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

type failingTrustMarks struct{ err error }

func (r failingTrustMarks) GetTrustMarkStatus(context.Context, string) (*string, error) {
	return nil, r.err
}

func (r failingTrustMarks) IssueTrustMark(context.Context, string, model.EntityIdentifier) (*string, error) {
	return nil, r.err
}

func (r failingTrustMarks) ListTrustMarks(context.Context, string, *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, r.err
}

type failingStatuses struct{ err error }

func (r failingStatuses) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	return nil, r.err
}

type failingListing struct{ err error }

func (r failingListing) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return nil, r.err
}

func TestServer_ARetrieversFiveHundredClassAnswersTheEndpointsFixedDescription(t *testing.T) {
	sub := url.QueryEscape("https://leaf.example.com")
	trustMarkType := url.QueryEscape("https://tm.example.com")
	endpoints := []struct {
		name        string
		request     func(ts *httptest.Server) (*http.Response, error)
		description string
	}{
		{name: "/fetch", description: subordinateRetrievalFailureError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().Get(ts.URL + "/fetch?sub=" + sub)
		}},
		{name: "/list", description: listingUnavailableError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().Get(ts.URL + "/list")
		}},
		{name: "/trust-mark", description: trustMarkUnavailableError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().Get(ts.URL + "/trust-mark?sub=" + sub + "&trust_mark_type=" + trustMarkType)
		}},
		{name: "/trust-mark-list", description: trustMarkListingUnavailableError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().Get(ts.URL + "/trust-mark-list?trust_mark_type=" + trustMarkType)
		}},
		{name: "/trust-mark-status", description: trustMarkStatusUnavailableError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().PostForm(ts.URL+"/trust-mark-status", url.Values{"trust_mark": {markIssuedBy(t, "https://ta.example.com")}})
		}},
		{name: "/subordinate-status", description: subordinateStatusUnavailableError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().Get(ts.URL + "/subordinate-status?sub=" + sub)
		}},
		{name: "/extended-list", description: extendedListingUnavailableError, request: func(ts *httptest.Server) (*http.Response, error) {
			return ts.Client().Get(ts.URL + "/extended-list")
		}},
	}
	failures := []struct {
		name        string
		reference   string
		err         error
		status      int
		code        string
		ownText     bool
		errorLogged bool
	}{
		{name: "a server error", reference: "8.9 server_error", err: model.NewServerError(retrieverLeak), status: http.StatusInternalServerError, code: model.ServerError, errorLogged: true},
		{name: "a temporarily unavailable store", reference: "8.9 temporarily_unavailable", err: model.NewTemporarilyUnavailableError(retrieverLeak), status: http.StatusServiceUnavailable, code: model.TemporarilyUnavailable},
		{name: "an invalid request", reference: "8.9 invalid_request", err: model.NewInvalidRequestError("the request names a record this store refuses"), status: http.StatusBadRequest, code: model.InvalidRequest, ownText: true},
	}

	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	for _, endpoint := range endpoints {
		for _, failure := range failures {
			t.Run(endpoint.name+" with "+failure.name, func(t *testing.T) {
				logs := &lockedBuffer{}
				server := NewServer(model.ServerConfiguration{
					Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
					EntityIdentifier:            "https://ta.example.com",
					SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
					EntityConfigurationLifetime: time.Hour,
					IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
					MetadataRetriever:           failingStore{err: failure.err},
					TrustMarkRetriever:          failingTrustMarks{err: failure.err},
					Extensions: model.Extensions{
						ExtendedListing:   model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: failingListing{err: failure.err}},
						SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: failingStatuses{err: failure.err}},
					},
				})
				mux := http.NewServeMux()
				server.Configure(mux)
				ts := httptest.NewServer(mux)
				t.Cleanup(ts.Close)

				response, err := endpoint.request(ts)
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
				description := endpoint.description
				if failure.ownText {
					description = "the request names a record this store refuses"
				}
				if response.StatusCode != failure.status || answer["error"] != failure.code || answer["error_description"] != description {
					t.Errorf("[%s] expected %d %s %q, got %d %s", failure.reference, failure.status, failure.code, description, response.StatusCode, raw)
				}
				if strings.Contains(string(raw), retrieverLeak) {
					t.Errorf("a retriever's text for this server's own condition must not reach the caller, got %s", raw)
				}

				logged := false
				for _, line := range strings.Split(logs.String(), "\n") {
					if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, retrieverLeak) {
						logged = true
					}
				}
				if logged != failure.errorLogged {
					t.Errorf("expected the retriever's cause logged at error level to be %t, got %s", failure.errorLogged, logs.String())
				}
				if !failure.ownText {
					if lines := strings.Count(logs.String(), retrieverLeak); lines != 1 {
						t.Errorf("expected the retriever's cause logged once for one failure, got %d lines: %s", lines, logs.String())
					}
				}
			})
		}
	}
}

type failingListingStore struct{ failingStore }

func (s failingListingStore) ListSubordinates(context.Context, model.SubordinateListingFilter) ([]model.EntityIdentifier, error) {
	return nil, s.err
}

func TestServer_List_AListingRetrieversFiveHundredClassAnswersTheFixedDescription(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	for name, failure := range map[string]struct {
		err         error
		status      int
		description string
		errorLogged bool
	}{
		"a server error":                  {err: model.NewServerError(retrieverLeak), status: http.StatusInternalServerError, description: subordinateListingUnavailableError, errorLogged: true},
		"a temporarily unavailable store": {err: model.NewTemporarilyUnavailableError(retrieverLeak), status: http.StatusServiceUnavailable, description: subordinateListingUnavailableError},
		"an invalid request":              {err: model.NewInvalidRequestError("the filter names a type this store refuses"), status: http.StatusBadRequest, description: "the filter names a type this store refuses"},
	} {
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuffer{}
			server := NewServer(model.ServerConfiguration{
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				MetadataRetriever:           failingListingStore{failingStore{err: failure.err}},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/list")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil || response.StatusCode != failure.status || answer["error_description"] != failure.description {
				t.Errorf("[8.9] expected %d %q, got %d %s", failure.status, failure.description, response.StatusCode, raw)
			}
			logged := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, retrieverLeak) {
					logged = true
				}
			}
			if logged != failure.errorLogged {
				t.Errorf("expected the retriever's cause logged at error level to be %t, got %s", failure.errorLogged, logs.String())
			}
		})
	}
}
