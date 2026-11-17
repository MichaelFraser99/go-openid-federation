package server

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func (f superiorMetadataFederation) registerConstraints(t *testing.T, constraints *model.Constraints) {
	t.Helper()
	f.anchor.cfg.IntermediateConfiguration.AddSubordinate(model.EntityIdentifier(f.leafURL), &model.SubordinateConfiguration{
		JWKs:        josemodel.Jwks{Keys: []map[string]any{f.leafKey}},
		Constraints: constraints,
	})
}

func (f superiorMetadataFederation) resolveStatus(t *testing.T) int {
	t.Helper()
	response, err := f.anchorServer.Client().Get(f.anchorServer.URL + "/resolve?sub=" + url.QueryEscape(f.leafURL) + "&trust_anchor=" + url.QueryEscape(f.anchorServer.URL))
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func TestServer_Fetch_IssuesTheConfiguredConstraints(t *testing.T) {
	zero := 0
	negative := -1

	t.Run("the configured constraints", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, map[string]any{})
		f.registerConstraints(t, &model.Constraints{
			MaxPathLength:      &zero,
			NamingConstraints:  &model.NamingConstraints{Permitted: []string{"example.com"}},
			AllowedEntityTypes: []string{"oauth_resource"},
		})

		status, claims := f.fetch(t)
		if status != http.StatusOK {
			t.Fatalf("expected the statement, got %d", status)
		}
		want := map[string]any{
			"max_path_length":      float64(0),
			"naming_constraints":   map[string]any{"permitted": []any{"example.com"}},
			"allowed_entity_types": []any{"oauth_resource"},
		}
		if !reflect.DeepEqual(claims["constraints"], want) {
			t.Errorf("[6.2] expected exactly the configured constraints, got %#v", claims["constraints"])
		}
	})

	t.Run("no constraints claim when none is configured", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, map[string]any{})
		f.registerConstraints(t, nil)

		_, claims := f.fetch(t)
		if _, present := claims["constraints"]; present {
			t.Errorf("expected no constraints claim, got %#v", claims["constraints"])
		}
	})

	for name, constraints := range map[string]*model.Constraints{
		"a negative max_path_length":                    {MaxPathLength: &negative},
		"allowed_entity_types naming federation_entity": {AllowedEntityTypes: []string{"federation_entity"}},
	} {
		t.Run(name+" is not published", func(t *testing.T) {
			f := startSuperiorMetadataFederation(t, map[string]any{})
			f.registerConstraints(t, constraints)

			if status, _ := f.fetch(t); status != http.StatusInternalServerError {
				t.Errorf("[6.2] expected constraints this library would refuse to answer 500, got %d", status)
			}
		})
	}
}

func TestServer_Resolve_EnforcesTheConstraintsASuperiorIssues(t *testing.T) {
	leafMetadata := map[string]any{
		"oauth_resource": map[string]any{"resource_name": "Leaf API"},
		"oauth_client":   map[string]any{"client_name": "Leaf client"},
	}
	zero := 0

	t.Run("allowed_entity_types removes the other entity types", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.registerConstraints(t, &model.Constraints{AllowedEntityTypes: []string{"oauth_resource"}})

		resolved := f.resolve(t)
		if _, present := resolved["oauth_client"]; present {
			t.Errorf("[6.2.3] expected oauth_client to be removed, got %#v", resolved)
		}
		if _, present := resolved["oauth_resource"]; !present {
			t.Errorf("[6.2.3] expected oauth_resource to stay, got %#v", resolved)
		}
	})

	t.Run("naming constraints that do not permit the subject refuse the chain", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.registerConstraints(t, &model.Constraints{NamingConstraints: &model.NamingConstraints{Permitted: []string{"example.com"}}})

		if status := f.resolveStatus(t); status == http.StatusOK {
			t.Errorf("[6.2.2] expected the chain to be refused, got %d", status)
		}
	})

	t.Run("a max_path_length of zero allows the immediate subordinate", func(t *testing.T) {
		f := startSuperiorMetadataFederation(t, leafMetadata)
		f.registerConstraints(t, &model.Constraints{MaxPathLength: &zero})

		if status := f.resolveStatus(t); status != http.StatusOK {
			t.Errorf("[6.2.1] expected the chain with no intermediate to resolve, got %d", status)
		}
	})
}
