package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_JudgesOnlyTheEntityTypesRequested(t *testing.T) {
	tests := map[string]struct {
		query  string
		status int
	}{
		"no entity_type, so every type is requested": {status: http.StatusBadRequest},
		"the broken type":                    {query: "&entity_type=openid_relying_party", status: http.StatusBadRequest},
		"a complete type and the broken one": {query: "&entity_type=federation_entity&entity_type=openid_relying_party", status: http.StatusBadRequest},
		"only the complete type":             {query: "&entity_type=federation_entity", status: http.StatusOK},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := startSuperiorMetadataFederation(t, map[string]any{
				"federation_entity":    map[string]any{"organization_name": "Leaf"},
				"openid_relying_party": map[string]any{"client_name": "Leaf RP"},
			})
			f.register(t, nil, model.MetadataPolicy{})

			response, err := f.anchorServer.Client().Get(f.anchorServer.URL + "/resolve?sub=" + url.QueryEscape(f.leafURL) + "&trust_anchor=" + url.QueryEscape(f.anchorServer.URL) + tc.query)
			if tc.status == http.StatusOK {
				metadata := decodeResolveMetadata(t, response, err)
				if _, present := metadata["openid_relying_party"]; present {
					t.Errorf("[6.1.4.2] the broken type MUST NOT be used, got %v", metadata["openid_relying_party"])
				}
				if _, present := metadata["federation_entity"]; !present {
					t.Errorf("[8.3.1] expected the requested federation_entity, got %v", metadata)
				}
				return
			}
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil || response.StatusCode != tc.status || answer["error"] != model.InvalidMetadata {
				t.Errorf("[6.1.4.2] expected %d invalid_metadata for a requested type that is broken, got %d %s", tc.status, response.StatusCode, raw)
			}
		})
	}
}
