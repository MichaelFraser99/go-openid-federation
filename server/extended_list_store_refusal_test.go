package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type refusesOneSubordinate struct {
	recordStore
	refusal error
}

func (s refusesOneSubordinate) GetSubordinate(ctx context.Context, identifier model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	if identifier == badSubordinate {
		return nil, s.refusal
	}
	return s.recordStore.GetSubordinate(ctx, identifier)
}

func TestServer_ExtendedList_OneSubordinateTheStoreRefusesLosesOnlyItsOwnStatement(t *testing.T) {
	tests := []struct {
		name       string
		refusal    error
		status     int
		code       string
		errorLines bool
	}{
		{name: "an invalid request", refusal: model.NewInvalidRequestError("the record's key is malformed"), status: http.StatusOK, errorLines: true},
		{name: "an unsupported parameter", refusal: model.NewUnsupportedParameterError("the record uses a feature this store does not support"), status: http.StatusOK, errorLines: true},
		{name: "an invalid trust chain", refusal: model.NewInvalidTrustChainError("the record is quarantined"), status: http.StatusOK, errorLines: true},
		{name: "an invalid issuer", refusal: model.NewInvalidIssuerError("the record names another issuer"), status: http.StatusOK, errorLines: true},
		{name: "not found", refusal: model.NewNotFoundError("no such subordinate"), status: http.StatusOK},
		{name: "an invalid subject", refusal: model.NewInvalidSubjectError("no such subordinate"), status: http.StatusOK},
		{name: "a temporarily unavailable store", refusal: model.NewTemporarilyUnavailableError("the store is throttling"), status: http.StatusServiceUnavailable, code: model.TemporarilyUnavailable},
		{name: "a store fault", refusal: model.NewServerError("the store failed"), status: http.StatusInternalServerError, code: model.ServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			subordinate, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			public, err := jwk.PublicJwk(subordinate.Public())
			if err != nil {
				t.Fatalf("failed to read a public key: %v", err)
			}
			(*public)["kid"] = "good"
			logs := &lockedBuffer{}
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				MetadataRetriever: refusesOneSubordinate{
					recordStore: recordStore{goodSubordinate: {JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}}},
					refusal:     tc.refusal,
				},
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: twoEntityListing{}},
				},
				Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("expected %d, got %d %s", tc.status, response.StatusCode, raw)
			}
			if tc.code != "" {
				var answer map[string]string
				if err := json.Unmarshal(raw, &answer); err != nil || answer["error"] != tc.code {
					t.Errorf("[8.9] a store that fails for every entry answers for the page, expected %s, got %s", tc.code, raw)
				}
				return
			}

			var listing model.ExtendedListingResponse
			if err := json.Unmarshal(raw, &listing); err != nil {
				t.Fatalf("failed to read the listing: %v", err)
			}
			statements := map[string]bool{}
			for _, entry := range listing.ImmediateSubordinateEntities {
				id, _ := entry["id"].(string)
				_, statements[id] = entry["subordinate_statement"]
			}
			if present, listed := statements[goodSubordinate]; !listed || !present {
				t.Errorf("one refused record must not take the listing down for the others, got %s", raw)
			}
			if present, listed := statements[badSubordinate]; !listed || present {
				t.Errorf("expected the refused subordinate listed without a statement, got %s", raw)
			}

			named := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, badSubordinate) {
					named = true
				}
			}
			if named != tc.errorLines {
				t.Errorf("expected an error-level line naming the refused subordinate to be %t, got %s", tc.errorLines, logs.String())
			}
			if tc.errorLines {
				_, code := errorStatusAndCode(tc.refusal)
				if !strings.Contains(logs.String(), `"error_code":"`+code+`"`) {
					t.Errorf("expected the store's class %s in the log, got %s", code, logs.String())
				}
			}
		})
	}
}
