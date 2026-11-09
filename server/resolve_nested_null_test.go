package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_RelaysANestedNullTheSubjectPublished(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the anchor signer: %v", err)
	}
	s := NewServer(model.ServerConfiguration{
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
		EntityConfigurationLifetime: 10 * time.Minute,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
		EntityConfiguration: model.EntityStatement{Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{
			"nested": map[string]any{"b": nil, "c": []any{nil}},
		}}},
	})
	mux := http.NewServeMux()
	s.Configure(mux)
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	s.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
	s.SetHttpClient(ts.Client())

	payloadOf := func(t *testing.T, path string) []byte {
		t.Helper()
		response, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer response.Body.Close() //nolint:errcheck
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("failed to read the response: %v", err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from %s, got %d %s", path, response.StatusCode, raw)
		}
		parts := strings.Split(string(raw), ".")
		if len(parts) != 3 {
			t.Fatalf("expected a signed statement from %s, got %s", path, raw)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to decode the payload from %s: %v", path, err)
		}
		return payload
	}
	nestedOf := func(t *testing.T, payload []byte) any {
		t.Helper()
		var statement struct {
			Metadata struct {
				FederationEntity map[string]any `json:"federation_entity"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(payload, &statement); err != nil {
			t.Fatalf("failed to read the statement: %v", err)
		}
		return statement.Metadata.FederationEntity["nested"]
	}

	want := map[string]any{"b": nil, "c": []any{nil}}
	if published := nestedOf(t, payloadOf(t, "/.well-known/openid-federation")); !reflect.DeepEqual(published, want) {
		t.Fatalf("expected the entity configuration to publish %v, got %v", want, published)
	}
	if resolved := nestedOf(t, payloadOf(t, "/resolve?sub="+ts.URL+"&trust_anchor="+ts.URL)); !reflect.DeepEqual(resolved, want) {
		t.Errorf("[8.3.2] the resolved metadata must carry the value the subject published, want %v, got %v", want, resolved)
	}
}
