package server

import (
	"io"
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
