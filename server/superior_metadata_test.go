package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/model_test"
)

type superiorMetadataFederation struct {
	anchor       *Server
	anchorServer *httptest.Server
	leafURL      string
	leafKey      map[string]any
}

func startSuperiorMetadataFederation(t *testing.T, leafMetadata map[string]any) superiorMetadataFederation {
	t.Helper()
	leafSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the leaf signer: %v", err)
	}
	leafJWK, err := jwk.PublicJwk(leafSigner.Public())
	if err != nil {
		t.Fatalf("failed to build the leaf jwk: %v", err)
	}
	(*leafJWK)["kid"] = "leaf"
	anchorSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the anchor signer: %v", err)
	}

	anchor := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: anchorSigner, KeyID: "anchor"},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
	})
	anchorMux := http.NewServeMux()
	anchor.Configure(anchorMux)
	anchorServer := httptest.NewTLSServer(anchorMux)
	t.Cleanup(anchorServer.Close)
	anchor.SetEntityIdentifier(model.EntityIdentifier(anchorServer.URL))
	anchor.SetHttpClient(anchorServer.Client())

	leafMux := http.NewServeMux()
	var leafURL string
	leafMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, _ *http.Request) {
		token, err := jwt.New(leafSigner, map[string]any{"kid": "leaf", "typ": "entity-statement+jwt", "alg": "ES256"}, map[string]any{
			"iss":             leafURL,
			"sub":             leafURL,
			"iat":             time.Now().Add(-time.Minute).UTC().Unix(),
			"exp":             time.Now().Add(10 * time.Minute).UTC().Unix(),
			"jwks":            map[string]any{"keys": []any{*leafJWK}},
			"authority_hints": []any{anchorServer.URL},
			"metadata":        leafMetadata,
		}, jwt.Opts{Algorithm: jwa.ES256})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(*token))
	})
	leaf := httptest.NewTLSServer(leafMux)
	t.Cleanup(leaf.Close)
	leafURL = leaf.URL

	return superiorMetadataFederation{anchor: anchor, anchorServer: anchorServer, leafURL: leafURL, leafKey: *leafJWK}
}

func (f superiorMetadataFederation) register(t *testing.T, metadata *model.Metadata, policy model.MetadataPolicy) {
	t.Helper()
	f.anchor.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(f.leafURL), &model.SubordinateConfiguration{
		JWKs:     josemodel.Jwks{Keys: []map[string]any{f.leafKey}},
		Metadata: metadata,
		Policies: policy,
	})
}

func (f superiorMetadataFederation) fetch(t *testing.T) (int, map[string]any) {
	t.Helper()
	response, err := f.anchorServer.Client().Get(f.anchorServer.URL + "/fetch?sub=" + url.QueryEscape(f.leafURL))
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the fetch response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil
	}
	parts := strings.Split(string(raw), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the statement: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to parse the statement: %v", err)
	}
	return response.StatusCode, claims
}

func (f superiorMetadataFederation) resolve(t *testing.T) map[string]any {
	t.Helper()
	response, err := f.anchorServer.Client().Get(f.anchorServer.URL + "/resolve?sub=" + url.QueryEscape(f.leafURL) + "&trust_anchor=" + url.QueryEscape(f.anchorServer.URL))
	return decodeResolveMetadata(t, response, err)
}

func TestServer_Fetch_IssuesTheConfiguredMetadataClaim(t *testing.T) {
	t.Run("the configured entity types and parameters, an empty array included", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, map[string]any{})
		f.register(t, &model.Metadata{OAuthResourceMetadata: &model.OAuthResourceMetadata{
			"api_resources":    []any{},
			"scopes_supported": []any{"read", "write"},
		}}, model.MetadataPolicy{})

		status, claims := f.fetch(t)
		if status != http.StatusOK {
			t.Fatalf("expected the statement, got %d", status)
		}
		want := map[string]any{"oauth_resource": map[string]any{"api_resources": []any{}, "scopes_supported": []any{"read", "write"}}}
		if !reflect.DeepEqual(claims["metadata"], want) {
			t.Errorf("[3.1.1] expected exactly the configured metadata, with [] kept, got %#v", claims["metadata"])
		}
	})

	t.Run("no metadata claim when none is configured", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, map[string]any{})
		f.register(t, nil, model.MetadataPolicy{})

		status, claims := f.fetch(t)
		if status != http.StatusOK {
			t.Fatalf("expected the statement, got %d", status)
		}
		if _, present := claims["metadata"]; present {
			t.Errorf("expected no metadata claim, got %#v", claims["metadata"])
		}
	})

	t.Run("a nil parameter is left out rather than written as null", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, map[string]any{})
		f.register(t, &model.Metadata{OAuthResourceMetadata: &model.OAuthResourceMetadata{"api_resources": nil, "resource_name": "Pinned"}}, model.MetadataPolicy{})

		_, claims := f.fetch(t)
		resource, _ := claims["metadata"].(map[string]any)["oauth_resource"].(map[string]any)
		if _, present := resource["api_resources"]; present || resource["resource_name"] != "Pinned" {
			t.Errorf("[3.2 step 16] expected the nil parameter to be left out, got %#v", resource)
		}
	})

	t.Run("metadata this library would refuse is not published", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, map[string]any{})
		f.register(t, &model.Metadata{OAuthResourceMetadata: &model.OAuthResourceMetadata{"jwks_uri": "http://insecure.example.com/jwks"}}, model.MetadataPolicy{})

		if status, _ := f.fetch(t); status != http.StatusInternalServerError {
			t.Errorf("expected a statement carrying refused metadata to answer 500, got %d", status)
		}
	})
}

func TestServer_Resolve_AppliesTheMetadataASuperiorIssues(t *testing.T) {
	leafMetadata := map[string]any{
		"oauth_resource": map[string]any{
			"resource_name":    "Leaf API",
			"api_resources":    []any{"https://leaf.example.com/self-published"},
			"scopes_supported": []any{"read", "write", "admin"},
		},
	}

	t.Run("the superior's values replace the subject's, and its other parameters stay", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.register(t, &model.Metadata{OAuthResourceMetadata: &model.OAuthResourceMetadata{
			"api_resources":    []any{"https://api.example.com/directory-listed"},
			"scopes_supported": []any{"read", "write", "delete"},
		}}, model.MetadataPolicy{})

		resource, _ := f.resolve(t)["oauth_resource"].(map[string]any)
		if !reflect.DeepEqual(resource["api_resources"], []any{"https://api.example.com/directory-listed"}) {
			t.Errorf("[3.1.1] expected the superior's api_resources, got %#v", resource["api_resources"])
		}
		if resource["resource_name"] != "Leaf API" {
			t.Errorf("[3.1.1] expected the subject's other parameters to stay, got %#v", resource)
		}
	})

	t.Run("an empty array from the superior replaces the subject's values", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.register(t, &model.Metadata{OAuthResourceMetadata: &model.OAuthResourceMetadata{"api_resources": []any{}}}, model.MetadataPolicy{})

		resource, _ := f.resolve(t)["oauth_resource"].(map[string]any)
		if got, ok := resource["api_resources"].([]any); !ok || len(got) != 0 {
			t.Errorf("[3.1.1] expected an empty api_resources, got %#v", resource["api_resources"])
		}
	})

	t.Run("a subset_of in the policy filters the superior's value", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.register(t, &model.Metadata{OAuthResourceMetadata: &model.OAuthResourceMetadata{
			"scopes_supported": []any{"read", "write", "delete"},
		}}, model.MetadataPolicy{OAuthResourceMetadata: map[string]model.PolicyOperators{
			"scopes_supported": {Metadata: []model.MetadataPolicyOperator{model_test.NewSubsetOf(t, []any{"read", "write", "admin"})}},
		}})

		resource, _ := f.resolve(t)["oauth_resource"].(map[string]any)
		if !reflect.DeepEqual(resource["scopes_supported"], []any{"read", "write"}) {
			t.Errorf("[6.1.4.2] expected the superior's metadata applied before the policy, got %#v", resource["scopes_supported"])
		}
	})

	t.Run("metadata for an entity type the subject does not publish is not applied", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.register(t, &model.Metadata{OpenIDRelyingPartyMetadata: &model.OpenIDRelyingPartyMetadata{"client_name": "Directory"}}, model.MetadataPolicy{})

		if resolved, present := f.resolve(t)["openid_relying_party"]; present {
			t.Errorf("[3.1.1] expected no openid_relying_party in the resolved metadata, got %#v", resolved)
		}
	})
}
