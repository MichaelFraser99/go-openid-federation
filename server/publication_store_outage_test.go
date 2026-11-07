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
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type publicationStore struct {
	subordinate *model.SubordinateConfiguration
	signersErr  error
}

func (s publicationStore) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return s.subordinate, nil
}

func (s publicationStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return map[model.EntityIdentifier]*model.SubordinateConfiguration{}, nil
}

func (s publicationStore) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	if s.signersErr != nil {
		return nil, s.signersErr
	}
	return []model.SignerConfiguration{*s.subordinate.SignerConfiguration}, nil
}

type publicationIssuerStore struct{ err error }

func (s publicationIssuerStore) ListTrustMarkIssuers(context.Context) (map[string][]model.EntityIdentifier, error) {
	if s.err != nil {
		return nil, s.err
	}
	return map[string][]model.EntityIdentifier{}, nil
}

func TestServer_AStoreOutageBehindThePublishedKeySetKeepsItsClassButNotItsText(t *testing.T) {
	const marker = "STORE-CONNECTION-STRING-ZZZZ"

	newSigner := func(t *testing.T, kid string) (model.SignerConfiguration, map[string]any) {
		t.Helper()
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		public, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("failed to read a public key: %v", err)
		}
		(*public)["kid"] = kid
		return model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: kid}, *public
	}

	temporary := fmt.Errorf("%w%s", model.ErrTemporarilyUnavailable, marker)
	plain := errors.New(marker)
	notFound := fmt.Errorf("%w%s", model.ErrNotFound, marker)

	tests := []struct {
		name        string
		path        string
		signersErr  error
		issuersErr  error
		status      int
		code        string
		description string
	}{
		{name: "the entity configuration while the store is healthy", path: "/.well-known/openid-federation", status: http.StatusOK},
		{name: "the entity configuration while the store cannot list subordinate signers for now", path: "/.well-known/openid-federation", signersErr: temporary, status: http.StatusServiceUnavailable, code: model.TemporarilyUnavailable, description: entityConfigurationUnavailableError},
		{name: "the entity configuration while the store fails to list subordinate signers", path: "/.well-known/openid-federation", signersErr: plain, status: http.StatusInternalServerError, code: model.ServerError, description: entityConfigurationUnavailableError},
		{name: "the entity configuration while the store reports its subordinate signers as not found", path: "/.well-known/openid-federation", signersErr: notFound, status: http.StatusInternalServerError, code: model.ServerError, description: entityConfigurationUnavailableError},
		{name: "the entity configuration while the store cannot list trust mark issuers for now", path: "/.well-known/openid-federation", issuersErr: temporary, status: http.StatusServiceUnavailable, code: model.TemporarilyUnavailable, description: entityConfigurationUnavailableError},
		{name: "the entity configuration while the store fails to list trust mark issuers", path: "/.well-known/openid-federation", issuersErr: plain, status: http.StatusInternalServerError, code: model.ServerError, description: entityConfigurationUnavailableError},
		{name: "the entity configuration while the store reports trust mark issuers as not found", path: "/.well-known/openid-federation", issuersErr: notFound, status: http.StatusInternalServerError, code: model.ServerError, description: entityConfigurationUnavailableError},
		{name: "a statement signed by a subordinate's own signer while the store is healthy", path: "/fetch?sub=" + url.QueryEscape("https://leaf.example.com"), status: http.StatusOK},
		{name: "a statement signed by a subordinate's own signer while the store cannot list subordinate signers for now", path: "/fetch?sub=" + url.QueryEscape("https://leaf.example.com"), signersErr: temporary, status: http.StatusServiceUnavailable, code: model.TemporarilyUnavailable, description: subordinateRetrievalFailureError},
		{name: "a statement signed by a subordinate's own signer while the store fails to list subordinate signers", path: "/fetch?sub=" + url.QueryEscape("https://leaf.example.com"), signersErr: plain, status: http.StatusInternalServerError, code: model.ServerError, description: subordinateRetrievalFailureError},
		{name: "the extended listing with statements while the store is healthy", path: "/extended-list?claims=subordinate_statement", status: http.StatusOK},
		{name: "the extended listing with statements while the store cannot list subordinate signers for now", path: "/extended-list?claims=subordinate_statement", signersErr: temporary, status: http.StatusServiceUnavailable, code: model.TemporarilyUnavailable, description: extendedListingUnavailableError},
		{name: "the extended listing with statements while the store fails to list subordinate signers", path: "/extended-list?claims=subordinate_statement", signersErr: plain, status: http.StatusInternalServerError, code: model.ServerError, description: extendedListingUnavailableError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := newSigner(t, "ta")
			leafSigner, leafJWK := newSigner(t, "leaf-signer")
			logs := &lockedBuffer{}
			cfg := model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         signer,
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				MetadataRetriever: publicationStore{
					subordinate: &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{leafJWK}}, SignerConfiguration: &leafSigner},
					signersErr:  tc.signersErr,
				},
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: listingWithOneEntity{}},
				},
				Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
			}
			if tc.issuersErr != nil {
				cfg.TrustMarkIssuerRetriever = publicationIssuerStore{err: tc.issuersErr}
			}
			server := NewServer(cfg)
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("the handler did not answer: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if response.StatusCode != tc.status {
				t.Fatalf("[8.9] expected %d, got %d %s", tc.status, response.StatusCode, raw)
			}
			if strings.Contains(string(raw), marker) {
				t.Errorf("[8.9] the store describes this server's own publication, so its text must not reach the caller: %s", raw)
			}
			if strings.Contains(logs.String(), "whose key is not the one this authority publishes") {
				t.Errorf("a store that could not list the published keys was logged as a signer whose key is not published: %s", logs.String())
			}
			if injected := tc.signersErr != nil || tc.issuersErr != nil; injected && strings.Count(logs.String(), marker) != 1 {
				t.Errorf("expected the store's own error logged once, where its cause is known, got %s", logs.String())
			}
			if tc.signersErr != nil && strings.Contains(logs.String(), "error creating subordinate statement") {
				t.Errorf("expected the cause loadSubordinate logged not to be logged again by the handler, got %s", logs.String())
			}
			if tc.code == "" {
				if tc.path == "/extended-list?claims=subordinate_statement" && !strings.Contains(string(raw), `"subordinate_statement":"`) {
					t.Errorf("expected the healthy listing to carry the statement, got %s", raw)
				}
				return
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil {
				t.Fatalf("failed to read the error: %v", err)
			}
			if answer["error"] != tc.code || answer["error_description"] != tc.description {
				t.Errorf("[8.9] expected %s %q, got %s", tc.code, tc.description, raw)
			}
		})
	}
}
