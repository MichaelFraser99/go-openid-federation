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

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
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

func TestServer_ExtendedList_AnEmptyListStillCarriesTheCursor(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.Extensions = model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: emptyListRetriever{}},
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
	if got := body["next"]; got != "opaque-cursor-7" {
		t.Errorf("an empty but non-nil entity list must still carry the cursor, got %v", got)
	}
}

type emptyListRetriever struct{}

func (emptyListRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	next := "opaque-cursor-7"
	return &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{}, Next: &next}, nil
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
			if want := "this endpoint accepts " + test.allowed; body["error_description"] != want {
				t.Errorf("expected the description %q, got %q", want, body["error_description"])
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

			getResponse, err := ts.Client().Get(ts.URL + path)
			if err != nil {
				t.Fatalf("failed to make the comparison request: %v", err)
			}
			defer getResponse.Body.Close() //nolint:errcheck

			if response.StatusCode != getResponse.StatusCode {
				t.Errorf("expected HEAD to answer as GET does (%d), got %d", getResponse.StatusCode, response.StatusCode)
			}
			if got, want := response.Header.Get("Content-Type"), getResponse.Header.Get("Content-Type"); got != want {
				t.Errorf("expected HEAD to carry GET's content type %q, got %q", want, got)
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

	t.Run("the cap is sixty four", func(t *testing.T) {
		if maxRequestedClaims != 64 {
			t.Errorf("the documented cap is 64, got %d", maxRequestedClaims)
		}
	})

	t.Run("duplicates and empty items do not count towards the cap", func(t *testing.T) {
		values := []string{""}
		for range 10 {
			values = append(values, "claim-000000,")
		}
		unique := make([]string, maxRequestedClaims)
		for i := range unique {
			unique[i] = fmt.Sprintf("claim-%06d", i)
		}
		values = append(values, strings.Join(unique, ","))

		filter, _, err := parseExtendedListingFilter(url.Values{"claims": values}, 10)
		if err != nil {
			t.Fatalf("the request names %d distinct claims, which is within the cap, got: %v", maxRequestedClaims, err)
		}
		if len(filter.Claims) != maxRequestedClaims {
			t.Errorf("expected %d distinct claims, got %d", maxRequestedClaims, len(filter.Claims))
		}
	})

	t.Run("a duplicate after the cap is reached", func(t *testing.T) {
		unique := make([]string, maxRequestedClaims)
		for i := range unique {
			unique[i] = fmt.Sprintf("claim-%06d", i)
		}

		cases := map[string]url.Values{
			"as a repeated parameter":  {"claims": {strings.Join(unique, ","), unique[0]}},
			"as a trailing comma item": {"claims": {strings.Join(unique, ",") + "," + unique[0]}},
		}

		for name, query := range cases {
			t.Run(name, func(t *testing.T) {
				filter, _, err := parseExtendedListingFilter(query, 10)
				if err != nil {
					t.Fatalf("the request names %d distinct claims, so repeating one is still within the cap, got: %v", maxRequestedClaims, err)
				}
				if len(filter.Claims) != maxRequestedClaims {
					t.Errorf("expected %d distinct claims, got %d", maxRequestedClaims, len(filter.Claims))
				}
			})
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
		const floodSize = 200000
		flood := build(floodSize)

		started := time.Now()
		_, _, err := parseExtendedListingFilter(flood, 10)
		elapsed := time.Since(started)

		if err == nil {
			t.Error("expected the flood to be refused")
		}
		if elapsed > 10*time.Second {
			t.Errorf("refusing a flood of %d values took %v, so the parse walks the input rather than stopping at the cap", floodSize, elapsed)
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

	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode the error response: %v", err)
	}
	if body["error_description"] != extendedListingUnavailableError {
		t.Errorf("the store's own message must not reach the caller, got %q", body["error_description"])
	}
}

func TestServer_AnUnknownMethodTokenIsNotHandledByTheLibrary(t *testing.T) {
	var logged strings.Builder
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	})

	request, err := http.NewRequest(strings.Repeat("M", 4096), ts.URL+"/.well-known/openid-federation", nil)
	if err != nil {
		t.Fatalf("failed to build the request: %v", err)
	}
	response, err := ts.Client().Do(request)
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected the mux to refuse a method the library registers no pattern for, got %d", response.StatusCode)
	}
	if logged.Len() != 0 {
		t.Errorf("such a method must not reach the library's handler, %d bytes were logged", logged.Len())
	}
}

func TestServer_ConfigureCoexistsWithConsumerRoutes(t *testing.T) {
	noop := func(http.ResponseWriter, *http.Request) {}

	tests := []string{
		"GET /",
		"POST /",
		"/",
		"GET /{anything}",
		"POST /{anything...}",
		"GET /.well-known/{name}",
		"POST /fetch/",
		"POST /api/fetch",
	}

	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			for _, consumerFirst := range []bool{true, false} {
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							t.Fatalf("mounting the federation routes beside %q panicked (consumer first: %v): %v", pattern, consumerFirst, recovered)
						}
					}()
					server := NewServer(model.ServerConfiguration{
						IntermediateConfiguration: &model.IntermediateConfiguration{},
						TrustMarkRetriever:        nilListingTrustMarkRetriever{},
						Extensions: model.Extensions{
							ExtendedListing:   model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: cursorRetriever{}},
							SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: emptyStatusRetriever{}},
						},
					})
					mux := http.NewServeMux()
					if consumerFirst {
						mux.HandleFunc(pattern, noop)
						server.Configure(mux)
						return
					}
					server.Configure(mux)
					mux.HandleFunc(pattern, noop)
				}()
			}
		})
	}
}

func TestServer_RouteNamesEveryMethodItServes(t *testing.T) {
	server := NewServer(model.ServerConfiguration{})
	mux := http.NewServeMux()
	server.route(mux, "/two", func(w http.ResponseWriter, _ *http.Request) ResponseFunc {
		return func() { w.WriteHeader(http.StatusNoContent) }
	}, http.MethodGet, http.MethodPost)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		request, err := http.NewRequest(method, ts.URL+"/two", nil)
		if err != nil {
			t.Fatalf("failed to build the request: %v", err)
		}
		response, err := ts.Client().Do(request)
		if err != nil {
			t.Fatalf("failed to make the request: %v", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Errorf("expected %s to reach the handler, got %d", method, response.StatusCode)
		}
	}

	request, err := http.NewRequest(http.MethodPut, ts.URL+"/two", nil)
	if err != nil {
		t.Fatalf("failed to build the request: %v", err)
	}
	response, err := ts.Client().Do(request)
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if got := response.Header.Get("Allow"); got != "GET, HEAD, POST" {
		t.Errorf("expected every served method in Allow, got %q", got)
	}
}

func TestServer_ExtendedList_TheReferenceRetrieverReportsAStaleCursor(t *testing.T) {
	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.Extensions = model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: TestExtendedRetriever{}},
		}
	})

	response, err := ts.Client().Get(ts.URL + "/extended-list?from=" + url.QueryEscape("https://never-listed.example.com"))
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode the error response: %v", err)
	}
	if body["error"] != model.PageNotFound {
		t.Errorf("expected the reference retriever to report a stale cursor as %q, got %q with status %d", model.PageNotFound, body["error"], response.StatusCode)
	}
}

type cachedListingRetriever struct {
	entities []map[string]any
}

func (c *cachedListingRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return &model.ExtendedListingResponse{ImmediateSubordinateEntities: c.entities}, nil
}

func TestServer_ExtendedList_DoesNotWriteIntoTheRetrieversEntities(t *testing.T) {
	const leaf = model.EntityIdentifier("https://leaf.example.com")

	leafSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the leaf signer: %v", err)
	}
	leafJWK, err := jwk.PublicJwk(leafSigner.Public())
	if err != nil {
		t.Fatalf("failed to build the leaf jwk: %v", err)
	}
	(*leafJWK)["alg"] = "ES256"

	retriever := &cachedListingRetriever{entities: []map[string]any{{"id": string(leaf)}}}
	intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
	intermediate.AddSubordinate(leaf, &model.SubordinateConfiguration{
		JWKs: josemodel.Jwks{Keys: []map[string]any{*leafJWK}},
	})

	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.IntermediateConfiguration = intermediate
		cfg.Extensions = model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: retriever},
		}
	})

	for range 2 {
		response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
		if err != nil {
			t.Fatalf("failed to make the request: %v", err)
		}
		raw, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatalf("failed to read the listing: %v", err)
		}
		if !strings.Contains(string(raw), "subordinate_statement") {
			t.Fatalf("this test only means something when a statement is issued, got %s", raw)
		}
	}

	if _, written := retriever.entities[0]["subordinate_statement"]; written {
		t.Error("the handler wrote a signed statement into the retriever's own map, which a cached response shares between callers")
	}
	if len(retriever.entities[0]) != 1 {
		t.Errorf("expected the retriever's map to be untouched, got %v", retriever.entities[0])
	}
}

func TestServer_ExtendedList_AnUnclassifiedSigningFailureKeepsItsTextOffTheWire(t *testing.T) {
	intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
	intermediate.AddSubordinate("https://leaf.example.com", &model.SubordinateConfiguration{})

	ts := contractServer(t, func(cfg *model.ServerConfiguration) {
		cfg.IntermediateConfiguration = intermediate
		cfg.Extensions = model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: listingWithOneEntity{}},
		}
	})

	response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
	if err != nil {
		t.Fatalf("failed to make the request: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected an unclassified signing failure to answer 500, got %d", response.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode the error response: %v", err)
	}
	if body["error_description"] != extendedListingUnavailableError {
		t.Errorf("the signer's own message must not reach the caller, got %q", body["error_description"])
	}
}

func TestServer_ExtendedList_BoundsTheRepeatedFilters(t *testing.T) {
	for _, parameter := range []string{"entity_type", "trust_mark_type"} {
		t.Run(parameter, func(t *testing.T) {
			values := make([]string, maxRepeatedFilterValues+1)
			for i := range values {
				values[i] = fmt.Sprintf("https://type.example.com/%d", i)
			}

			if _, _, err := parseExtendedListingFilter(url.Values{parameter: values}, 10); err == nil {
				t.Errorf("expected more than %d values of %q to be refused", maxRepeatedFilterValues, parameter)
			} else if !errors.Is(err, model.ErrInvalidRequest) {
				t.Errorf("expected an invalid request, got %T: %v", err, err)
			}

			if _, _, err := parseExtendedListingFilter(url.Values{parameter: values[:maxRepeatedFilterValues]}, 10); err != nil {
				t.Errorf("no error expected at the cap, got: %v", err)
			}
		})
	}
}

func TestErrorStatusAndCode_AResolverLimitIsNotAServerFault(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "a limit the resolver reached while walking",
			err:        model.NewLimitReachedError("the resolver reached the maximum trust chain depth before a trust anchor"),
			wantStatus: http.StatusNotFound,
			wantCode:   model.InvalidTrustAnchor,
		},
		{
			name:       "an unreachable trust anchor",
			err:        model.NewInvalidTrustAnchorError("unable to build trust chain from specified 'sub' to specified 'trust_anchor'"),
			wantStatus: http.StatusNotFound,
			wantCode:   model.InvalidTrustAnchor,
		},
		{
			name:       "a fault of this server",
			err:        model.NewServerError("the signer is unavailable"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   model.ServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, code := errorStatusAndCode(tc.err)
			if status != tc.wantStatus || code != tc.wantCode {
				t.Errorf("expected %d %s, got %d %s", tc.wantStatus, tc.wantCode, status, code)
			}
		})
	}
}
