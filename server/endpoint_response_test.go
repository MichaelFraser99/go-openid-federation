package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

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

type emptyPageRetriever struct{}

func (emptyPageRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	next := "opaque-cursor-42"
	return &model.ExtendedListingResponse{Next: &next}, nil
}

func TestServer_ExtendedList_AnEmptyPageStillCarriesTheCursor(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.Extensions = model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: emptyPageRetriever{}},
		}
	})

	response, err := ts.Client().Get(ts.URL + "/extended-list")
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode the listing: %v", err)
	}

	entities, present := body["immediate_subordinate_entities"]
	if !present {
		t.Fatalf("the listing carries no entity array: %v", body)
	}
	if _, isArray := entities.([]any); !isArray {
		t.Errorf("expected an array of entities, got %T", entities)
	}
	if got := body["next"]; got != "opaque-cursor-42" {
		t.Errorf("a page with no entities must still carry the cursor for the next one, got %v", got)
	}
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
		{name: "well known", path: "/.well-known/openid-federation", method: http.MethodPut, allowed: "GET, HEAD"},
		{name: "list", path: "/list", method: http.MethodPost, allowed: "GET, HEAD"},
		{name: "fetch", path: "/fetch", method: http.MethodPost, allowed: "GET, HEAD"},
		{name: "resolve", path: "/resolve", method: http.MethodPost, allowed: "GET, HEAD"},
		{name: "extended list", path: "/extended-list", method: http.MethodPost, allowed: "GET, HEAD"},
		{name: "subordinate status", path: "/subordinate-status", method: http.MethodPost, allowed: "GET, HEAD"},
		{name: "trust mark", path: "/trust-mark", method: http.MethodPost, allowed: "GET, HEAD"},
		{name: "trust mark list", path: "/trust-mark-list", method: http.MethodPost, allowed: "GET, HEAD"},
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

func TestServer_HeadIsServedWhereverGetIs(t *testing.T) {
	ts := endpointServer(t)

	for _, path := range []string{
		"/.well-known/openid-federation",
		"/list",
		"/fetch?sub=https://leaf.example.com",
		"/resolve?sub=https://leaf.example.com&trust_anchor=https://ta.example.com",
		"/extended-list",
		"/subordinate-status?sub=https://leaf.example.com",
		"/trust-mark?sub=https://leaf.example.com&trust_mark_type=https://tm.example.com/a",
		"/trust-mark-list?trust_mark_type=https://tm.example.com/a",
	} {
		t.Run(path, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodHead, ts.URL+path, nil)
			if err != nil {
				t.Fatalf("failed to build the request: %v", err)
			}
			response, err := ts.Client().Do(request)
			if err != nil {
				t.Fatalf("failed to make the request: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck

			if response.StatusCode == http.StatusMethodNotAllowed {
				t.Errorf("the method-less pattern shadowed the GET pattern, so HEAD is no longer served")
			}
		})
	}
}

func TestServer_ExtendedList_BoundsTheRequestedClaimCount(t *testing.T) {
	build := func(count int) url.Values {
		claims := make([]string, count)
		for i := range claims {
			claims[i] = fmt.Sprintf("claim-%06d", i)
		}
		return url.Values{"claims": {strings.Join(claims, ",")}}
	}

	t.Run("at the cap", func(t *testing.T) {
		filter, _, err := parseExtendedListingFilter(build(maxRequestedClaims), 10)
		if err != nil {
			t.Fatalf("no error expected at the cap, got: %v", err)
		}
		if len(filter.Claims) != maxRequestedClaims {
			t.Errorf("expected %d claims, got %d", maxRequestedClaims, len(filter.Claims))
		}
	})

	t.Run("one past the cap", func(t *testing.T) {
		if _, _, err := parseExtendedListingFilter(build(maxRequestedClaims+1), 10); err == nil {
			t.Error("expected a request naming more claims than the cap to be refused")
		} else if !errors.Is(err, model.ErrInvalidRequest) {
			t.Errorf("expected an invalid request, got %T: %v", err, err)
		}
	})

	t.Run("a caller supplied flood is refused quickly", func(t *testing.T) {
		started := time.Now()
		if _, _, err := parseExtendedListingFilter(build(200000), 10); err == nil {
			t.Error("expected the flood to be refused")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Errorf("refusing a flood took %v, so the parse is not bounded by the cap", elapsed)
		}
	})
}

func TestServer_ExtendedList_DegenerateClaimsValues(t *testing.T) {
	tests := []struct {
		name              string
		query             string
		expectClaims      []string
		subordinateWanted bool
	}{
		{name: "no value", query: "claims=", expectClaims: nil},
		{name: "only separators", query: "claims=,,,", expectClaims: nil},
		{name: "only whitespace", query: "claims=" + url.QueryEscape("   "), expectClaims: nil},
		{name: "only subordinate_statement", query: "claims=subordinate_statement", expectClaims: []string{}, subordinateWanted: true},
		{name: "a value beside separators", query: "claims=,trust_marks,", expectClaims: []string{"trust_marks"}},
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
			if subordinateStatement != test.subordinateWanted {
				t.Errorf("expected subordinate_statement requested=%v, got %v", test.subordinateWanted, subordinateStatement)
			}
			if test.expectClaims == nil {
				if filter.Claims != nil {
					t.Errorf("expected no claim filter, got %#v", filter.Claims)
				}
				return
			}
			if !slices.Equal(filter.Claims, test.expectClaims) {
				t.Errorf("expected %#v, got %#v", test.expectClaims, filter.Claims)
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

type listingWithOneEntity struct{}

func (listingWithOneEntity) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return &model.ExtendedListingResponse{
		ImmediateSubordinateEntities: []map[string]any{{"id": "https://leaf.example.com"}},
	}, nil
}

type unavailableSubordinateStore struct{}

func (unavailableSubordinateStore) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, model.NewTemporarilyUnavailableError("the subordinate store is down for maintenance")
}

func (unavailableSubordinateStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, model.NewTemporarilyUnavailableError("the subordinate store is down for maintenance")
}

func (unavailableSubordinateStore) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, model.NewTemporarilyUnavailableError("the subordinate store is down for maintenance")
}

func TestServer_ExtendedList_AClassifiedStoreErrorChoosesTheStatus(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.MetadataRetriever = unavailableSubordinateStore{}
		cfg.Extensions = model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: listingWithOneEntity{}},
		}
	})

	response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusServiceUnavailable {
		raw, _ := io.ReadAll(response.Body)
		t.Errorf("expected the store's own classification to choose the status, got %d with %s", response.StatusCode, raw)
	}
}

func TestServer_AnUnsupportedMethodDoesNotLogTheWholeRequestLine(t *testing.T) {
	var logged strings.Builder
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	})

	method := strings.Repeat("M", 4096)
	request, err := http.NewRequest(method, ts.URL+"/.well-known/openid-federation", nil)
	if err != nil {
		t.Fatalf("failed to build the request: %v", err)
	}
	response, err := ts.Client().Do(request)
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if logged.Len() > 2048 {
		t.Errorf("a caller chose %d bytes of method and the log grew by %d, so the log is unbounded", len(method), logged.Len())
	}
}
