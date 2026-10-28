package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func selfReferenceServer(t *testing.T, own model.EntityIdentifier, setLegacyIss, registerItself, extendedList bool) *httptest.Server {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public jwk, got %q", err.Error())
	}

	intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
	if registerItself {
		intermediate.AddSubordinate(own, &model.SubordinateConfiguration{
			JWKs: josemodel.Jwks{Keys: []map[string]any{*public}},
		})
	}

	cfg := model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    signer,
			KeyID:     (*public)["kid"].(string),
		},
		EntityIdentifier:          own,
		IntermediateConfiguration: intermediate,
	}
	if setLegacyIss {
		cfg.EntityConfiguration = model.EntityStatement{Iss: own}
	}
	if extendedList {
		cfg.Extensions.ExtendedListing.Enabled = true
		cfg.Extensions.ExtendedListing.MetadataRetriever = &testExtendedListingRetriever{
			result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{
				{"id": string(own)},
				{"id": "https://genuine.example.com"},
			}},
		}
	}

	srv := NewServer(cfg)
	mux := http.NewServeMux()
	srv.Configure(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestFetch_RefusesTheServersOwnIdentifierAsInvalidRequest(t *testing.T) {
	tests := map[string]struct {
		own            model.EntityIdentifier
		setLegacyIss   bool
		registerItself bool
	}{
		"the identifier the README advises configuring, and nothing else": {
			own: "https://ta.example.com",
		},
		"the same, with the server registered in its own subordinate store": {
			own:            "https://ta.example.com",
			registerItself: true,
		},
		"the same, with EntityConfiguration.Iss also set by hand": {
			own:          "https://ta.example.com",
			setLegacyIss: true,
		},
		"an identifier carrying a trailing slash": {
			own: "https://ta.example.com/",
		},
		"an identifier carrying a trailing slash, registered in its own store": {
			own:            "https://ta.example.com/",
			registerItself: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := selfReferenceServer(t, test.own, test.setLegacyIss, test.registerItself, false)

			response, err := server.Client().Get(fmt.Sprintf("%s/fetch?sub=%s", server.URL, url.QueryEscape(string(test.own))))
			if err != nil {
				t.Fatalf("expected no transport error, got %q", err.Error())
			}
			defer response.Body.Close() //nolint:errcheck
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("[8.1.2] returning invalid_request is RECOMMENDED when 'sub' references the issuing entity, got %d (%s)", response.StatusCode, body)
			}
			var answer struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(body, &answer); err != nil {
				t.Fatalf("expected a json error object, got %s", body)
			}
			if answer.Error != "invalid_request" {
				t.Errorf("[8.1.2] expected the invalid_request error code, got %q", answer.Error)
			}
		})
	}
}

func TestFetch_StillDistinguishesAnUnknownSubject(t *testing.T) {
	const own = model.EntityIdentifier("https://ta.example.com")
	server := selfReferenceServer(t, own, false, true, false)

	response, err := server.Client().Get(fmt.Sprintf("%s/fetch?sub=%s", server.URL, url.QueryEscape("https://unknown.example.com")))
	if err != nil {
		t.Fatalf("expected no transport error, got %q", err.Error())
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(response.Body)
		t.Errorf("a subject that is simply not registered is still not_found, not the self-reference refusal, got %d (%s)", response.StatusCode, body)
	}
}

func TestExtendedList_OmitsTheServersOwnEntryRatherThanFailingTheListing(t *testing.T) {
	const own = model.EntityIdentifier("https://ta.example.com")
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public jwk, got %q", err.Error())
	}

	intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
	intermediate.AddSubordinate(own, &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}})
	intermediate.AddSubordinate("https://genuine.example.com", &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}})

	srv := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    signer,
			KeyID:     (*public)["kid"].(string),
		},
		EntityIdentifier:          own,
		IntermediateConfiguration: intermediate,
		Configuration:             model.Configuration{Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))},
		Extensions: model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{
				Enabled:   true,
				SizeLimit: 10,
				MetadataRetriever: &testExtendedListingRetriever{
					result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{
						{"id": string(own)},
						{"id": "https://genuine.example.com"},
					}},
				},
			},
		},
	})
	mux := http.NewServeMux()
	srv.Configure(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	response, err := server.Client().Get(fmt.Sprintf("%s/extended-list?claims=subordinate_statement", server.URL))
	if err != nil {
		t.Fatalf("expected no transport error, got %q", err.Error())
	}
	defer response.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("one entry that cannot be issued for must not take down the listing for every other subordinate, got %d (%s)", response.StatusCode, body)
	}

	var listing model.ExtendedListingResponse
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("expected a json listing, got %s", body)
	}
	if len(listing.ImmediateSubordinateEntities) != 2 {
		t.Fatalf("expected both entries to be listed, got %d", len(listing.ImmediateSubordinateEntities))
	}
	for _, entry := range listing.ImmediateSubordinateEntities {
		_, issued := entry["subordinate_statement"]
		if entry["id"] == string(own) && issued {
			t.Error("no entity issues a subordinate statement about itself, so the server's own entry must carry none")
		}
		if entry["id"] == "https://genuine.example.com" && !issued {
			t.Error("a genuine subordinate must still get its statement when another entry is skipped")
		}
	}
}

func TestFetch_RefusesEverySpellingOfItsOwnIdentifier(t *testing.T) {
	const own = model.EntityIdentifier("https://ta.example.com")

	tests := map[string]struct {
		asked   string
		refused bool
	}{
		"the identifier exactly as configured":   {asked: "https://ta.example.com", refused: true},
		"the host in a different case":           {asked: "https://TA.example.com", refused: true},
		"a trailing slash":                       {asked: "https://ta.example.com/", refused: true},
		"the default https port stated":          {asked: "https://ta.example.com:443", refused: true},
		"a fully qualified host, trailing dot":   {asked: "https://ta.example.com.", refused: true},
		"a path that resolves to the root":       {asked: "https://ta.example.com/a/..", refused: true},
		"a doubled slash":                        {asked: "https://ta.example.com//", refused: true},
		"a single dot segment":                   {asked: "https://ta.example.com/.", refused: true},
		"a genuine subordinate under a path":     {asked: "https://ta.example.com/genuine"},
		"a genuine subordinate on another host":  {asked: "https://leaf.example.com"},
		"a non default port is a different host": {asked: "https://ta.example.com:8443"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("expected no error creating signer, got %q", err.Error())
			}
			public, err := jwk.PublicJwk(signer.Public())
			if err != nil {
				t.Fatalf("expected no error creating public jwk, got %q", err.Error())
			}

			intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
			intermediate.AddSubordinate(model.EntityIdentifier(test.asked), &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{*public}},
			})

			srv := NewServer(model.ServerConfiguration{
				SignerConfiguration: model.SignerConfiguration{
					Algorithm: "ES256",
					Signer:    signer,
					KeyID:     (*public)["kid"].(string),
				},
				EntityIdentifier:          own,
				IntermediateConfiguration: intermediate,
			})
			mux := http.NewServeMux()
			srv.Configure(mux)
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			response, err := server.Client().Get(fmt.Sprintf("%s/fetch?sub=%s", server.URL, url.QueryEscape(test.asked)))
			if err != nil {
				t.Fatalf("expected no transport error, got %q", err.Error())
			}
			defer response.Body.Close() //nolint:errcheck
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if test.refused {
				if response.StatusCode != http.StatusBadRequest {
					t.Fatalf("[8.1.2] %q names the issuing entity, so no subordinate statement may be signed for it, got %d (%s)", test.asked, response.StatusCode, body)
				}
				return
			}
			if response.StatusCode != http.StatusOK {
				t.Errorf("[8.1.2] %q names a different entity and must still be served, got %d (%s)", test.asked, response.StatusCode, body)
			}
		})
	}
}

func TestExtendedList_OmitsTheServersOwnEntryUnderAnyEquivalentSpelling(t *testing.T) {
	const own = model.EntityIdentifier("https://ta.example.com")
	const respelled = "https://TA.example.com/"

	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public jwk, got %q", err.Error())
	}

	intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: 5 * time.Minute}
	intermediate.AddSubordinate(model.EntityIdentifier(respelled), &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}})
	intermediate.AddSubordinate("https://genuine.example.com", &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}})

	srv := NewServer(model.ServerConfiguration{
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    signer,
			KeyID:     (*public)["kid"].(string),
		},
		EntityIdentifier:          own,
		IntermediateConfiguration: intermediate,
		Extensions: model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{
				Enabled:   true,
				SizeLimit: 10,
				MetadataRetriever: &testExtendedListingRetriever{
					result: &model.ExtendedListingResponse{ImmediateSubordinateEntities: []map[string]any{
						{"id": respelled},
						{"id": "https://genuine.example.com"},
					}},
				},
			},
		},
	})
	mux := http.NewServeMux()
	srv.Configure(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	response, err := server.Client().Get(fmt.Sprintf("%s/extended-list?claims=subordinate_statement", server.URL))
	if err != nil {
		t.Fatalf("expected no transport error, got %q", err.Error())
	}
	defer response.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("one entry that cannot be issued for must not take down the listing, got %d (%s)", response.StatusCode, body)
	}

	var listing model.ExtendedListingResponse
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("expected a json listing, got %s", body)
	}
	for _, entry := range listing.ImmediateSubordinateEntities {
		_, issued := entry["subordinate_statement"]
		if entry["id"] == respelled && issued {
			t.Errorf("[8.1.2] %q is another spelling of this server's own identifier, so it must carry no subordinate statement", respelled)
		}
		if entry["id"] == "https://genuine.example.com" && !issued {
			t.Error("a genuine subordinate must still get its statement")
		}
	}
}
