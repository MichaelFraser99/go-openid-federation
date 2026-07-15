package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type testListingRetriever struct {
	TestRetriever
	received *model.SubordinateListingFilter
	result   []model.EntityIdentifier
	err      error
}

func (r *testListingRetriever) ListSubordinates(_ context.Context, filter model.SubordinateListingFilter) ([]model.EntityIdentifier, error) {
	r.received = &filter
	return r.result, r.err
}

func startListServer(t *testing.T, cfg model.ServerConfiguration) *httptest.Server {
	t.Helper()
	server := NewServer(cfg)
	m := http.NewServeMux()
	server.Configure(m)
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	return s
}

func TestServer_List_DelegatesToRetriever(t *testing.T) {
	retriever := &testListingRetriever{
		result: []model.EntityIdentifier{"https://rp.example.com", "https://op.example.com"},
	}
	s := startListServer(t, model.ServerConfiguration{
		IntermediateConfiguration: &model.IntermediateConfiguration{},
		MetadataRetriever:         retriever,
	})

	query := url.Values{
		"entity_type":     {"openid_provider", "openid_relying_party"},
		"trust_marked":    {"true"},
		"trust_mark_type": {"https://tm.example.com/verified"},
		"intermediate":    {"false"},
	}
	resp, err := s.Client().Get(s.URL + "/list?" + query.Encode())
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if retriever.received == nil {
		t.Fatal("expected the listing retriever to receive the filter")
	}
	got := *retriever.received
	if !slices.Equal(got.EntityTypes, []string{"openid_provider", "openid_relying_party"}) {
		t.Errorf("unexpected entity types: %v", got.EntityTypes)
	}
	if got.TrustMarked == nil || *got.TrustMarked != true {
		t.Errorf("expected trust_marked true, got %v", got.TrustMarked)
	}
	if got.TrustMarkType == nil || *got.TrustMarkType != "https://tm.example.com/verified" {
		t.Errorf("expected trust_mark_type, got %v", got.TrustMarkType)
	}
	if got.Intermediate == nil || *got.Intermediate != false {
		t.Errorf("expected intermediate false, got %v", got.Intermediate)
	}

	assertListBody(t, resp, []string{"https://rp.example.com", "https://op.example.com"})
}

func TestServer_List_RetrieverErrorPropagates(t *testing.T) {
	retriever := &testListingRetriever{
		err: model.NewUnsupportedParameterError("parameter 'intermediate' is not supported"),
	}
	s := startListServer(t, model.ServerConfiguration{
		IntermediateConfiguration: &model.IntermediateConfiguration{},
		MetadataRetriever:         retriever,
	})

	resp, err := s.Client().Get(s.URL + "/list?intermediate=true")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	validateErrorResponse(t, resp, nil, http.StatusBadRequest, "unsupported_parameter", "parameter 'intermediate' is not supported")
}

func TestServer_List_FiltersWithoutRetriever(t *testing.T) {
	s := startListServer(t, model.ServerConfiguration{
		IntermediateConfiguration: &model.IntermediateConfiguration{},
	})

	resp, err := s.Client().Get(s.URL + "/list?entity_type=openid_provider")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	validateErrorResponse(t, resp, nil, http.StatusBadRequest, "unsupported_parameter", "subordinate listing filters are not supported")
}

func TestServer_List_MalformedBoolean(t *testing.T) {
	retriever := &testListingRetriever{}
	s := startListServer(t, model.ServerConfiguration{
		IntermediateConfiguration: &model.IntermediateConfiguration{},
		MetadataRetriever:         retriever,
	})

	resp, err := s.Client().Get(s.URL + "/list?trust_marked=notabool")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	validateErrorResponse(t, resp, nil, http.StatusBadRequest, "invalid_request", "parameter 'trust_marked' must be a boolean")

	if retriever.received != nil {
		t.Error("expected malformed request to be rejected before reaching the retriever")
	}
}

func assertListBody(t *testing.T, resp *http.Response, expected []string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	var got []string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("failed to unmarshal body %q: %v", body, err)
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d entities %v, got %d %v", len(expected), expected, len(got), got)
	}
	for _, e := range expected {
		if !slices.Contains(got, e) {
			t.Errorf("expected response to contain %q, got %v", e, got)
		}
	}
}
