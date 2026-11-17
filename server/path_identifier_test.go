package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_AnEntityIdentifierWithAPathIsServedWhenTheMuxIsMountedUnderIt(t *testing.T) {
	s := mustNewServer(t, model.ServerConfiguration{
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
	})
	federation := http.NewServeMux()
	s.Configure(federation)
	mux := http.NewServeMux()
	mux.Handle("/tenant/", http.StripPrefix("/tenant", federation))
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	identifier := ts.URL + "/tenant"
	s.SetEntityIdentifier(model.EntityIdentifier(identifier))

	get := func(t *testing.T, target string) (int, string, []byte) {
		t.Helper()
		response, err := ts.Client().Get(target)
		if err != nil {
			t.Fatalf("request to %s failed: %v", target, err)
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("failed to read %s: %v", target, err)
		}
		return response.StatusCode, response.Header.Get("Content-Type"), body
	}

	status, contentType, body := get(t, identifier+"/.well-known/openid-federation")
	if status != http.StatusOK || contentType != "application/entity-statement+jwt" {
		t.Fatalf("[9] expected the entity configuration at the identifier's well-known URL, got %d %q %s", status, contentType, body)
	}
	parts := strings.Split(string(body), ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %s", body)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the payload: %v", err)
	}
	var claims struct {
		Sub      string `json:"sub"`
		Metadata struct {
			FederationEntity map[string]any `json:"federation_entity"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to parse the payload: %v", err)
	}
	if claims.Sub != identifier {
		t.Errorf("expected sub %q, got %q", identifier, claims.Sub)
	}

	endpoints := 0
	for name, value := range claims.Metadata.FederationEntity {
		if !strings.HasSuffix(name, "_endpoint") {
			continue
		}
		endpoint, _ := value.(string)
		if !strings.HasPrefix(endpoint, identifier+"/") {
			t.Errorf("expected %s under the identifier, got %q", name, endpoint)
			continue
		}
		endpoints++
		status, contentType, body := get(t, endpoint)
		if status == http.StatusNotFound && !strings.HasPrefix(contentType, "application/json") {
			t.Errorf("expected the advertised %s %q to reach a handler, got %d %q %s", name, endpoint, status, contentType, body)
		}
	}
	if endpoints != 3 {
		t.Errorf("expected the fetch, list and resolve endpoints to be advertised, got %d", endpoints)
	}

	if status, _, _ := get(t, ts.URL+"/.well-known/openid-federation"); status != http.StatusNotFound {
		t.Errorf("expected no entity configuration at the host's root, which belongs to another identifier, got %d", status)
	}
}
