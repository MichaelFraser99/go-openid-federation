package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_ExtendedList_StrippingLeavesTheRetrieversEntriesUntouched(t *testing.T) {
	leaked := map[string]any{"kid": "leaked", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "SECRET"}
	good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
	jwks := map[string]any{"keys": []any{good, leaked}}
	entity := map[string]any{"id": "https://rp.example.com", "jwks": jwks}

	server := startExtendedListServer(t, statelessExtendedListingRetriever{
		result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{entity}},
	})

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := server.Client().Get(server.URL + "/extended-list?claims=jwks")
			if err != nil {
				t.Errorf("the extended listing did not answer: %v", err)
				return
			}
			_, _ = io.ReadAll(response.Body)
			_ = response.Body.Close()
		}()
	}
	wg.Wait()

	if keys, _ := jwks["keys"].([]any); len(keys) != 2 {
		t.Errorf("the listing rewrote the retriever's own key set, which is shared across every request: %d keys left of 2", len(keys))
	}
}

func TestServer_ExtendedList_ConcurrentListingsOfCleanKeysDoNotCrash(t *testing.T) {
	good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
	entity := map[string]any{
		"id":       "https://rp.example.com",
		"jwks":     map[string]any{"keys": []any{good}},
		"metadata": map[string]any{"openid_relying_party": map[string]any{"jwks": map[string]any{"keys": []any{good}}}},
	}

	server := startExtendedListServer(t, statelessExtendedListingRetriever{
		result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{entity}},
	})

	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				response, err := server.Client().Get(server.URL + "/extended-list?claims=jwks,metadata")
				if err != nil {
					t.Errorf("the extended listing did not answer: %v", err)
					return
				}
				_, _ = io.ReadAll(response.Body)
				_ = response.Body.Close()
			}
		}()
	}
	wg.Wait()
}

func TestServer_ExtendedList_DoesNotRepublishAPrivateKeyHeldInAGoShape(t *testing.T) {
	const marker = "SECRETEXPONENTVALUE"
	leaked := map[string]any{"kid": "leaked", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": marker}
	good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}

	shapes := map[string]any{
		"a decoded JSON key set":    map[string]any{"keys": []any{good, leaked}},
		"a typed slice of key maps": map[string]any{"keys": []map[string]any{good, leaked}},
		"a josemodel.Jwks value":    josemodel.Jwks{Keys: []map[string]any{good, leaked}},
		"a josemodel.Jwks pointer":  &josemodel.Jwks{Keys: []map[string]any{good, leaked}},
	}

	for name, jwks := range shapes {
		t.Run(name, func(t *testing.T) {
			retriever := &testExtendedListingRetriever{
				result: &model.ExtendedListingResponse{
					ImmediateSubordinateEntities: []map[string]any{{"id": "https://rp.example.com", "jwks": jwks}},
				},
			}
			server := startExtendedListServer(t, retriever)

			response, err := server.Client().Get(server.URL + "/extended-list?claims=jwks")
			if err != nil {
				t.Fatalf("the extended listing did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if response.StatusCode != http.StatusOK {
				t.Fatalf("a registrant's leaked key must not take the listing down, got %d: %s", response.StatusCode, raw)
			}
			if strings.Contains(string(raw), marker) {
				t.Errorf("the listing republished a registrant's private exponent written as %s: %s", name, raw)
			}
			if !strings.Contains(string(raw), "good") {
				t.Errorf("expected the usable key beside it to survive, got %s", raw)
			}
		})
	}
}

type statelessExtendedListingRetriever struct {
	result *model.ExtendedListingResponse
}

func (r statelessExtendedListingRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return r.result, nil
}
