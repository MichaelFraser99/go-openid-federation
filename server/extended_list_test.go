package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type testExtendedListingRetriever struct {
	received *model.ExtendedListingFilter
	result   *model.ExtendedListingResponse
	err      error
}

func (r *testExtendedListingRetriever) GetExtendedSubordinates(_ context.Context, filter model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	r.received = &filter
	if r.result == nil {
		r.result = &model.ExtendedListingResponse{}
	}
	return r.result, r.err
}

func startExtendedListServer(t *testing.T, retriever model.ExtendedListingRetriever) *httptest.Server {
	t.Helper()
	server := NewServer(model.ServerConfiguration{
		EntityIdentifier:          "https://some-trust-source.com",
		IntermediateConfiguration: &model.IntermediateConfiguration{},
		Extensions: model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{
				Enabled:           true,
				SizeLimit:         50,
				MetadataRetriever: retriever,
			},
		},
	})
	m := http.NewServeMux()
	server.Configure(m)
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	return s
}

func TestServer_ExtendedList_DelegatesFilterToRetriever(t *testing.T) {
	retriever := &testExtendedListingRetriever{
		result: &model.ExtendedListingResponse{
			ImmediateSubordinateEntities: []map[string]any{
				{"id": "https://rp.example.com"},
			},
		},
	}
	s := startExtendedListServer(t, retriever)

	query := url.Values{
		"entity_type":     {"openid_provider", "openid_relying_party"},
		"trust_marked":    {"true"},
		"trust_mark_type": {"https://tm.example.com/verified", "https://tm.example.com/certified"},
		"intermediate":    {"false"},
		"from":            {"https://rp.example.com"},
		"limit":           {"5"},
		"claims":          {"foo,bar"},
	}
	resp, err := s.Client().Get(s.URL + "/extended-list?" + query.Encode())
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d (response: %s)", resp.StatusCode, body)
	}

	if retriever.received == nil {
		t.Fatal("expected the extended listing retriever to receive the filter")
	}
	got := *retriever.received
	if !slices.Equal(got.EntityTypes, []string{"openid_provider", "openid_relying_party"}) {
		t.Errorf("unexpected entity types: %v", got.EntityTypes)
	}
	if got.TrustMarked == nil || *got.TrustMarked != true {
		t.Errorf("expected trust_marked true, got %v", got.TrustMarked)
	}
	if !slices.Equal(got.TrustMarkType, []string{"https://tm.example.com/verified", "https://tm.example.com/certified"}) {
		t.Errorf("expected repeatable trust_mark_type, got %v", got.TrustMarkType)
	}
	if got.Intermediate == nil || *got.Intermediate != false {
		t.Errorf("expected intermediate false, got %v", got.Intermediate)
	}
	if got.From == nil || string(*got.From) != "https://rp.example.com" {
		t.Errorf("expected from https://rp.example.com, got %v", got.From)
	}
	if got.Limit != 5 {
		t.Errorf("expected limit 5, got %d", got.Limit)
	}
	if !slices.Equal(got.Claims, []string{"foo", "bar"}) {
		t.Errorf("expected claims [foo bar], got %v", got.Claims)
	}
}

func TestServer_ExtendedList_LimitDefaultsToSizeLimit(t *testing.T) {
	retriever := &testExtendedListingRetriever{
		result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{}},
	}
	s := startExtendedListServer(t, retriever)

	resp, err := s.Client().Get(s.URL + "/extended-list")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if retriever.received == nil {
		t.Fatal("expected the extended listing retriever to receive the filter")
	}
	if retriever.received.Limit != 50 {
		t.Errorf("expected limit to default to configured size limit 50, got %d", retriever.received.Limit)
	}
}

func TestServer_ExtendedList_MalformedBoolean(t *testing.T) {
	tests := map[string]struct {
		query       string
		description string
	}{
		"trust_marked": {query: "trust_marked=notabool", description: "parameter 'trust_marked' must be a boolean"},
		"intermediate": {query: "intermediate=notabool", description: "parameter 'intermediate' must be a boolean"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			retriever := &testExtendedListingRetriever{}
			s := startExtendedListServer(t, retriever)

			resp, err := s.Client().Get(s.URL + "/extended-list?" + tt.query)
			validateErrorResponse(t, resp, err, http.StatusBadRequest, "invalid_request", tt.description)

			if retriever.received != nil {
				t.Error("expected malformed request to be rejected before reaching the retriever")
			}
		})
	}
}

func TestServer_ExtendedList_RetrieverErrorPropagates(t *testing.T) {
	tests := map[string]struct {
		err             error
		expectedStatus  int
		expectedError   string
		expectedMessage string
	}{
		"unsupported parameter": {
			err:             model.NewUnsupportedParameterError("parameter 'trust_marked' is not supported"),
			expectedStatus:  http.StatusBadRequest,
			expectedError:   "unsupported_parameter",
			expectedMessage: "parameter 'trust_marked' is not supported",
		},
		"invalid request": {
			err:             model.NewInvalidRequestError("parameter 'additional_identifier' must include a scheme"),
			expectedStatus:  http.StatusBadRequest,
			expectedError:   "invalid_request",
			expectedMessage: "parameter 'additional_identifier' must include a scheme",
		},
		"not found": {
			err:             model.NewNotFoundError("from cursor does not identify a subordinate"),
			expectedStatus:  http.StatusNotFound,
			expectedError:   "not_found",
			expectedMessage: "from cursor does not identify a subordinate",
		},
		"untyped error": {
			err:             errors.New("boom"),
			expectedStatus:  http.StatusInternalServerError,
			expectedError:   "server_error",
			expectedMessage: "boom",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			retriever := &testExtendedListingRetriever{err: tt.err}
			s := startExtendedListServer(t, retriever)

			resp, err := s.Client().Get(s.URL + "/extended-list")
			validateErrorResponse(t, resp, err, tt.expectedStatus, tt.expectedError, tt.expectedMessage)
		})
	}
}
