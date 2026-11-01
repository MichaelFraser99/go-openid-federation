package server

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Fetch_RefusesToSignWithASubordinateSignerWhoseKeyIsNotPublished(t *testing.T) {
	const refusedLine = "refusing to sign with a subordinate signer whose key is not the one this authority publishes under its key ID"

	newSigner := func(t *testing.T) josemodel.Signer {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}
	authority := newSigner(t)
	first := newSigner(t)
	second := newSigner(t)
	ed, err := jws.GetSigner(jwa.Ed25519, nil)
	if err != nil {
		t.Fatalf("failed to build an Ed25519 signer: %v", err)
	}
	subjectKey := newSigner(t)
	subjectJWK, err := jwk.PublicJwk(subjectKey.Public())
	if err != nil {
		t.Fatalf("failed to read the subject key: %v", err)
	}
	(*subjectJWK)["kid"] = "subject"

	const (
		a = model.EntityIdentifier("https://a.example.com")
		b = model.EntityIdentifier("https://b.example.com")
	)
	type subordinate struct {
		signer josemodel.Signer
		kid    string
	}

	tests := []struct {
		name         string
		subordinates map[model.EntityIdentifier]*subordinate
		algorithm    string
		refused      []model.EntityIdentifier
	}{
		{
			name:         "two subordinates claiming one key ID with different keys refuse the one whose key was left out",
			subordinates: map[model.EntityIdentifier]*subordinate{a: {first, "shared"}, b: {second, "shared"}},
			refused:      []model.EntityIdentifier{b},
		},
		{
			name:         "the same pair added the other way round still refuses the subject that sorts second",
			subordinates: map[model.EntityIdentifier]*subordinate{b: {first, "shared"}, a: {second, "shared"}},
			refused:      []model.EntityIdentifier{b},
		},
		{
			name:         "a subordinate signer reusing the authority's key ID with a different key is refused",
			subordinates: map[model.EntityIdentifier]*subordinate{a: {first, "ta"}},
			refused:      []model.EntityIdentifier{a},
		},
		{
			name:         "a subordinate signer the entity configuration leaves out for its algorithm is refused",
			subordinates: map[model.EntityIdentifier]*subordinate{a: {ed, "ed"}},
			algorithm:    "EdDSA",
			refused:      []model.EntityIdentifier{a},
		},
		{
			name:         "two subordinates sharing one signer under one key ID both sign",
			subordinates: map[model.EntityIdentifier]*subordinate{a: {first, "shared"}, b: {first, "shared"}},
		},
		{
			name:         "a subordinate signed by the authority's own signer under its key ID signs",
			subordinates: map[model.EntityIdentifier]*subordinate{a: {authority, "ta"}},
		},
		{
			name:         "a subordinate with no signer of its own is signed by the authority",
			subordinates: map[model.EntityIdentifier]*subordinate{a: nil},
		},
		{
			name:         "two subordinates under distinct key IDs both sign",
			subordinates: map[model.EntityIdentifier]*subordinate{a: {first, "one"}, b: {second, "two"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intermediate := &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour}
			for identifier, sub := range tc.subordinates {
				configuration := &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*subjectJWK}}}
				if sub != nil {
					algorithm := "ES256"
					if tc.algorithm != "" {
						algorithm = tc.algorithm
					}
					configuration.SignerConfiguration = &model.SignerConfiguration{Algorithm: algorithm, Signer: sub.signer, KeyID: sub.kid}
				}
				intermediate.AddSubordinate(identifier, configuration)
			}
			var logs bytes.Buffer
			ts := startFetchServer(t, model.ServerConfiguration{
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: authority, KeyID: "ta"},
				IntermediateConfiguration: intermediate,
				Configuration:             model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))},
			})
			published := publishedJWKs(t, ts)

			for identifier := range tc.subordinates {
				logs.Reset()
				status, body := fetchPath(t, ts, "/fetch?sub="+string(identifier))
				refused := false
				for _, r := range tc.refused {
					refused = refused || r == identifier
				}
				if refused {
					if status != http.StatusInternalServerError {
						t.Fatalf("[8.9] a statement no resolver could verify is this server's own fault, so %s must answer 500, got %d %s", identifier, status, body)
					}
					var answer map[string]string
					if err := json.Unmarshal([]byte(body), &answer); err != nil {
						t.Fatalf("failed to read the error body: %v", err)
					}
					if answer["error"] != model.ServerError || answer["error_description"] != subordinateSignerUnpublishedError {
						t.Errorf("[8.9] expected server_error with the fixed description, got %s", body)
					}
					if !loggedAtError(t, logs.String(), refusedLine) {
						t.Errorf("[CLAUDE.md] the operator must be told at Error why %s was refused, got logs %s", identifier, logs.String())
					}
					continue
				}
				if status != http.StatusOK {
					t.Fatalf("[8.1] expected %s to be served, got %d %s", identifier, status, body)
				}
				if loggedAtError(t, logs.String(), "") {
					t.Errorf("[CLAUDE.md] serving %s must not repeat the entity configuration's drop lines, got logs %s", identifier, logs.String())
				}
				header, err := base64.RawURLEncoding.DecodeString(strings.Split(body, ".")[0])
				if err != nil {
					t.Fatalf("failed to decode the statement header: %v", err)
				}
				var head struct {
					Kid string `json:"kid"`
				}
				if err := json.Unmarshal(header, &head); err != nil {
					t.Fatalf("failed to read the statement header: %v", err)
				}
				if err := entity_statement.VerifyAgainstJwks(context.Background(), body, head.Kid, published, model.DefaultSigningAlgorithms()); err != nil {
					t.Errorf("[3.1] a served subordinate statement must verify against the key set the authority publishes, %s did not: %v", identifier, err)
				}
			}
		})
	}
}

func TestServer_ExtendedList_ListsASubordinateWhoseSignerIsNotPublishedWithoutItsStatement(t *testing.T) {
	newSigner := func(t *testing.T) josemodel.Signer {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}
	authority := newSigner(t)
	subjectJWK, err := jwk.PublicJwk(newSigner(t).Public())
	if err != nil {
		t.Fatalf("failed to read the subject key: %v", err)
	}
	(*subjectJWK)["kid"] = "subject"

	intermediate := &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour}
	for identifier, signer := range map[model.EntityIdentifier]josemodel.Signer{"https://a.example.com": newSigner(t), "https://b.example.com": newSigner(t)} {
		intermediate.AddSubordinate(identifier, &model.SubordinateConfiguration{
			JWKs:                josemodel.Jwks{Keys: []map[string]any{*subjectJWK}},
			SignerConfiguration: &model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "shared"},
		})
	}
	intermediate.AddSubordinate("https://c.example.com", &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*subjectJWK}}})

	ts := startFetchServer(t, model.ServerConfiguration{
		SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: authority, KeyID: "ta"},
		IntermediateConfiguration: intermediate,
		Extensions: model.Extensions{ExtendedListing: model.ExtendedListingConfiguration{
			Enabled:   true,
			SizeLimit: 50,
			MetadataRetriever: &testExtendedListingRetriever{result: &model.ExtendedListingResponse{
				ImmediateSubordinateEntities: []map[string]any{{"id": "https://a.example.com"}, {"id": "https://b.example.com"}, {"id": "https://c.example.com"}},
			}},
		}},
	})

	status, body := fetchPath(t, ts, "/extended-list?claims=subordinate_statement")
	if status != http.StatusOK {
		t.Fatalf("[CLAUDE.md] one subordinate's signer must never take the listing down for the others, got %d %s", status, body)
	}
	var listing model.ExtendedListingResponse
	if err := json.Unmarshal([]byte(body), &listing); err != nil {
		t.Fatalf("failed to read the listing: %v", err)
	}
	expected := map[string]bool{"https://a.example.com": true, "https://b.example.com": false, "https://c.example.com": true}
	if len(listing.ImmediateSubordinateEntities) != len(expected) {
		t.Fatalf("expected every entity to be listed, got %s", body)
	}
	for _, entity := range listing.ImmediateSubordinateEntities {
		id, _ := entity["id"].(string)
		_, carried := entity["subordinate_statement"]
		if carried != expected[id] {
			t.Errorf("expected %s to carry a subordinate statement: %v, got %v", id, expected[id], carried)
		}
	}
}

func publishedJWKs(t *testing.T, ts *httptest.Server) josemodel.Jwks {
	t.Helper()
	status, body := fetchPath(t, ts, "/.well-known/openid-federation")
	if status != http.StatusOK {
		t.Fatalf("expected the entity configuration, got %d %s", status, body)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(body, ".")[1])
	if err != nil {
		t.Fatalf("failed to decode the entity configuration: %v", err)
	}
	var claims struct {
		JWKs josemodel.Jwks `json:"jwks"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to read the entity configuration: %v", err)
	}
	return claims.JWKs
}

func fetchPath(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	response, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}
	return response.StatusCode, string(raw)
}
