package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func endpointServer(t *testing.T) *httptest.Server {
	t.Helper()
	return contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.TrustMarkRetriever = nilListingTrustMarkRetriever{}
		cfg.Extensions = model.Extensions{
			ExtendedListing:   model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: cursorRetriever{}},
			SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: emptyStatusRetriever{}},
		}
	})
}

type cursorRetriever struct{}

func (cursorRetriever) GetExtendedSubordinates(_ context.Context, filter model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	if filter.From != nil {
		return nil, model.NewPageNotFoundError("the pagination pointer is no longer known")
	}
	return &model.ExtendedListingResponse{}, nil
}

type emptyStatusRetriever struct{}

func (emptyStatusRetriever) GetSubordinateStatus(context.Context, model.EntityIdentifier) (*model.SubordinateStatusResponse, error) {
	return &model.SubordinateStatusResponse{}, nil
}

func TestServer_ExtendedList_AnUnknownCursorIsPageNotFound(t *testing.T) {
	ts := endpointServer(t)

	response, err := ts.Client().Get(ts.URL + "/extended-list?from=" + url.QueryEscape("stale-cursor"))
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", response.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode the error response: %v", err)
	}
	if body["error"] != model.PageNotFound {
		t.Errorf("expected the %q error code, got %q", model.PageNotFound, body["error"])
	}
}

func TestServer_EveryRouteAnswersJSONToAnUnsupportedMethod(t *testing.T) {
	ts := endpointServer(t)

	tests := []struct {
		name    string
		path    string
		method  string
		allowed string
	}{
		{name: "well known", path: "/.well-known/openid-federation", method: http.MethodPut, allowed: http.MethodGet},
		{name: "list", path: "/list", method: http.MethodPost, allowed: http.MethodGet},
		{name: "fetch", path: "/fetch", method: http.MethodPost, allowed: http.MethodGet},
		{name: "resolve", path: "/resolve", method: http.MethodPost, allowed: http.MethodGet},
		{name: "extended list", path: "/extended-list", method: http.MethodPost, allowed: http.MethodGet},
		{name: "subordinate status", path: "/subordinate-status", method: http.MethodPost, allowed: http.MethodGet},
		{name: "trust mark", path: "/trust-mark", method: http.MethodPost, allowed: http.MethodGet},
		{name: "trust mark list", path: "/trust-mark-list", method: http.MethodPost, allowed: http.MethodGet},
		{name: "trust mark status", path: "/trust-mark-status", method: http.MethodGet, allowed: http.MethodPost},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(test.method, ts.URL+test.path, nil)
			if err != nil {
				t.Fatalf("failed to build the request: %v", err)
			}
			response, err := ts.Client().Do(request)
			if err != nil {
				t.Fatalf("failed to make the request: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("expected 405, got %d", response.StatusCode)
			}
			if got := response.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("expected a JSON content type, got %q", got)
			}
			if got := response.Header.Get("Allow"); got != test.allowed {
				t.Errorf("expected the Allow header to name %q, got %q", test.allowed, got)
			}

			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			var body map[string]string
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("the error response is not JSON: %v, got %s", err, raw)
			}
			if body["error"] != model.InvalidRequest {
				t.Errorf("expected the %q error code, got %q", model.InvalidRequest, body["error"])
			}
		})
	}
}

func TestServer_SupportedMethodsStillReachTheHandler(t *testing.T) {
	ts := endpointServer(t)

	response, err := ts.Client().Get(ts.URL + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusOK {
		t.Errorf("expected the GET route to still answer 200, got %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); !strings.Contains(got, "entity-statement+jwt") {
		t.Errorf("expected an entity statement, got content type %q", got)
	}
}

func TestServer_ExtendedList_CombinesRepeatedClaimsParameters(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{name: "repeated parameters", query: "claims=trust_marks&claims=subordinate_statement"},
		{name: "one comma separated parameter", query: "claims=trust_marks,subordinate_statement"},
		{name: "repeated and comma separated together", query: "claims=trust_marks,metadata&claims=subordinate_statement"},
		{name: "repeated with surrounding space", query: "claims=" + url.QueryEscape(" trust_marks ") + "&claims=" + url.QueryEscape(" subordinate_statement ")},
		{name: "a claim repeated across both forms", query: "claims=trust_marks,trust_marks&claims=trust_marks&claims=subordinate_statement"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, err := url.ParseQuery(test.query)
			if err != nil {
				t.Fatalf("failed to parse the fixture query: %v", err)
			}

			filter, subordinateStatement, err := parseExtendedListingFilter(query, 10)
			if err != nil {
				t.Fatalf("no error expected parsing the filter, got: %v", err)
			}
			if !subordinateStatement {
				t.Error("expected subordinate_statement to be requested")
			}
			if !slices.Contains(filter.Claims, "trust_marks") {
				t.Errorf("expected trust_marks to survive, got %v", filter.Claims)
			}
			if slices.Contains(filter.Claims, "subordinate_statement") {
				t.Errorf("subordinate_statement is handled separately and must not stay in the claims list, got %v", filter.Claims)
			}
			seen := make(map[string]bool, len(filter.Claims))
			for _, claim := range filter.Claims {
				if seen[claim] {
					t.Errorf("expected each claim once, got %v", filter.Claims)
				}
				seen[claim] = true
			}
		})
	}
}
