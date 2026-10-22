package server

import (
	"io"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_ExtendedList_DoesNotRepublishARegistrantsPrivateKey(t *testing.T) {
	const marker = "SECRETEXPONENTVALUE"

	leaked := map[string]any{"kid": "leaked", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": marker}
	good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}

	tests := []struct {
		name      string
		reference string
		claims    string
		entity    map[string]any
	}{
		{
			name:      "the top level jwks claim",
			reference: "RFC 7518 6.2.2",
			claims:    "jwks",
			entity: map[string]any{
				"id":   "https://rp.example.com",
				"jwks": map[string]any{"keys": []any{good, leaked}},
			},
		},
		{
			name:      "a metadata jwks parameter",
			reference: "RFC 7518 6.2.2",
			claims:    "metadata",
			entity: map[string]any{
				"id":       "https://rp.example.com",
				"metadata": map[string]any{"openid_relying_party": map[string]any{"jwks": map[string]any{"keys": []any{good, leaked}}}},
			},
		},
		{
			name:      "a metadata policy operand",
			reference: "RFC 7518 6.2.2",
			claims:    "metadata_policy",
			entity: map[string]any{
				"id":              "https://rp.example.com",
				"metadata_policy": map[string]any{"openid_relying_party": map[string]any{"jwks": map[string]any{"value": map[string]any{"keys": []any{leaked}}}}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			retriever := &testExtendedListingRetriever{
				result: &model.ExtendedListingResponse{
					ImmediateSubordinateEntities: []map[string]any{tc.entity},
				},
			}
			server := startExtendedListServer(t, retriever)

			response, err := server.Client().Get(server.URL + "/extended-list?claims=" + tc.claims)
			if err != nil {
				t.Fatalf("the extended listing did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if response.StatusCode != http.StatusOK {
				t.Fatalf("[%s] a registrant's leaked key must not take the listing down, got %d: %s", tc.reference, response.StatusCode, raw)
			}
			if strings.Contains(string(raw), marker) {
				t.Errorf("[%s] the listing republished a registrant's private exponent: %s", tc.reference, raw)
			}
			if tc.claims != "metadata_policy" && !strings.Contains(string(raw), "good") {
				t.Errorf("[%s] expected the usable key beside it to survive, got %s", tc.reference, raw)
			}
		})
	}
}

func TestServer_ExtendedList_RefusesAnEntryTooDeepToScanForKeyMaterial(t *testing.T) {
	const marker = "SECRETEXPONENTVALUE"
	leaked := map[string]any{"kid": "leaked", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": marker}

	nest := func(depth int, leaf any) any {
		value := leaf
		for range depth {
			value = map[string]any{"wrapper": value}
		}
		return value
	}

	tests := []struct {
		name       string
		reference  string
		depth      int
		wantStatus int
	}{
		{name: "a key set within the scan depth", reference: "RFC 7518 6.2.2", depth: 4, wantStatus: http.StatusOK},
		{name: "a key set beyond the scan depth", reference: "8.9", depth: 40, wantStatus: http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			retriever := &testExtendedListingRetriever{
				result: &model.ExtendedListingResponse{
					ImmediateSubordinateEntities: []map[string]any{{
						"id":       "https://rp.example.com",
						"metadata": nest(tc.depth, map[string]any{"jwks": map[string]any{"keys": []any{leaked}}}),
					}},
				},
			}
			server := startExtendedListServer(t, retriever)

			response, err := server.Client().Get(server.URL + "/extended-list?claims=metadata")
			if err != nil {
				t.Fatalf("the extended listing did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if response.StatusCode != tc.wantStatus {
				t.Errorf("[%s] expected %d, got %d: %s", tc.reference, tc.wantStatus, response.StatusCode, raw)
			}
			if strings.Contains(string(raw), marker) {
				t.Errorf("[%s] a strip that stops without saying so publishes the key it did not reach: %s", tc.reference, raw)
			}
		})
	}
}

func TestServer_ExtendedList_AnEntryItCannotSerialiseIsItsOwnFault(t *testing.T) {
	tests := []struct {
		name       string
		reference  string
		entity     map[string]any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "an entry that serialises",
			reference:  "8.9",
			entity:     map[string]any{"id": "https://rp.example.com", "metadata": map[string]any{}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "an entry holding a value JSON cannot represent",
			reference:  "8.9",
			entity:     map[string]any{"id": "https://rp.example.com", "metadata": map[string]any{"openid_relying_party": map[string]any{"ratio": math.NaN()}}},
			wantStatus: http.StatusInternalServerError,
			wantCode:   model.ServerError,
		},
		{
			name:       "an entry holding a value with no JSON representation at all",
			reference:  "8.9",
			entity:     map[string]any{"id": "https://rp.example.com", "metadata": map[string]any{"openid_relying_party": map[string]any{"callback": func() {}}}},
			wantStatus: http.StatusInternalServerError,
			wantCode:   model.ServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			retriever := &testExtendedListingRetriever{
				result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{tc.entity}},
			}
			server := startExtendedListServer(t, retriever)

			response, err := server.Client().Get(server.URL + "/extended-list?claims=metadata")
			if err != nil {
				t.Fatalf("the extended listing did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if response.StatusCode != tc.wantStatus {
				t.Fatalf("[%s] expected %d, got %d: %s", tc.reference, tc.wantStatus, response.StatusCode, raw)
			}
			if tc.wantCode == "" {
				return
			}
			if !strings.Contains(string(raw), `"`+tc.wantCode+`"`) {
				t.Errorf("[%s] an entry this server cannot serialise is its own fault, not a temporary condition, got %s", tc.reference, raw)
			}
		})
	}
}
