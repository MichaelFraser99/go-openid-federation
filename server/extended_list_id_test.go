package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type shapedExtendedRetriever struct {
	entities []map[string]any
}

func (r shapedExtendedRetriever) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return &model.ExtendedListingResponse{ImmediateSubordinateEntities: r.entities}, nil
}

func TestServer_ExtendedList_OmitsEntriesWhoseIdIsNotAnEntityIdentifier(t *testing.T) {
	const (
		first  = "https://first.example.com"
		second = "https://second.example.com"
	)

	tests := []struct {
		name       string
		entities   []map[string]any
		want       []string
		invalid    int
		duplicates int
	}{
		{
			name:     "every id an entity identifier",
			entities: []map[string]any{{"id": first}, {"id": second}},
			want:     []string{first, second},
		},
		{
			name:     "an id that is a number",
			entities: []map[string]any{{"id": 7}, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "an id that is a float, as a JSON round trip produces",
			entities: []map[string]any{{"id": float64(7)}, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "an id that is an object",
			entities: []map[string]any{{"id": map[string]any{"id": first}}, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "a string id that is not an entity identifier",
			entities: []map[string]any{{"id": first}, {"id": "not-an-entity-identifier"}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "a string id over plain http",
			entities: []map[string]any{{"id": "http://leaf.example.com"}, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "an empty string id",
			entities: []map[string]any{{"id": ""}, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "an absent id",
			entities: []map[string]any{{"other": "value"}, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:     "an entry that is nil",
			entities: []map[string]any{nil, {"id": first}},
			want:     []string{first},
			invalid:  1,
		},
		{
			name:       "an id listed twice, the first entry kept",
			entities:   []map[string]any{{"id": first, "registered": 1}, {"id": second}, {"id": first, "registered": 2}},
			want:       []string{first, second},
			duplicates: 1,
		},
		{
			name:     "every id malformed",
			entities: []map[string]any{{"id": 7}, {"id": "http://leaf.example.com"}},
			want:     []string{},
			invalid:  2,
		},
	}

	for _, claims := range []string{"", "?claims=subordinate_statement", "?claims=registered"} {
		for _, tc := range tests {
			t.Run(tc.name+claims, func(t *testing.T) {
				signer, err := jws.GetSigner(jwa.ES256, nil)
				if err != nil {
					t.Fatalf("failed to build the signer: %v", err)
				}
				var logs bytes.Buffer
				server := NewServer(model.ServerConfiguration{
					SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
					EntityConfigurationLifetime: time.Hour,
					IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
					Extensions: model.Extensions{
						ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: shapedExtendedRetriever{entities: tc.entities}},
					},
					Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, nil))},
				})
				for _, subject := range []string{first, second} {
					subordinateSigner, err := jws.GetSigner(jwa.ES256, nil)
					if err != nil {
						t.Fatalf("failed to build a subordinate key: %v", err)
					}
					public, err := jwk.PublicJwk(subordinateSigner.Public())
					if err != nil {
						t.Fatalf("failed to read a subordinate key: %v", err)
					}
					(*public)["kid"] = "sub"
					server.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(subject), &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}})
				}
				mux := http.NewServeMux()
				server.Configure(mux)
				ts := httptest.NewTLSServer(mux)
				defer ts.Close()
				server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
				server.SetHttpClient(ts.Client())

				response, err := ts.Client().Get(ts.URL + "/extended-list" + claims)
				if err != nil {
					t.Fatalf("the handler did not answer, which is what a panic looks like to a caller: %v", err)
				}
				defer response.Body.Close() //nolint:errcheck
				raw, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read the response: %v", err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("[Table 4] expected one entry's malformed id not to take down the page, got %d %s", response.StatusCode, raw)
				}
				var body struct {
					Entities []map[string]any `json:"immediate_subordinate_entities"`
				}
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatalf("failed to read the listing: %v", err)
				}
				got := []string{}
				for _, entity := range body.Entities {
					id, _ := entity["id"].(string)
					got = append(got, id)
					_, hasStatement := entity["subordinate_statement"]
					if hasStatement != (claims == "?claims=subordinate_statement") {
						t.Errorf("[Table 4] expected a subordinate statement for %s exactly when it is requested, got one=%t", id, hasStatement)
					}
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("[Table 4] expected the entries whose id is an entity identifier, each once and in order, %q, got %q", tc.want, got)
				}
				if tc.duplicates > 0 && body.Entities[0]["registered"] != float64(1) {
					t.Errorf("expected the first entry for a repeated id kept, got %v", body.Entities[0])
				}

				lines := omissionLines(t, logs.String())
				if tc.invalid == 0 && tc.duplicates == 0 {
					if len(lines) != 0 {
						t.Errorf("expected nothing logged as omitted, got %+v", lines)
					}
					return
				}
				if len(lines) != 1 {
					t.Fatalf("expected one omission line for the page, not one per entry, got %+v", lines)
				}
				if lines[0].Level != "ERROR" || lines[0].NotEntityIdentifiers != tc.invalid || lines[0].Duplicates != tc.duplicates {
					t.Errorf("expected an Error line counting %d malformed ids and %d duplicates, got %+v", tc.invalid, tc.duplicates, lines[0])
				}
			})
		}
	}
}
