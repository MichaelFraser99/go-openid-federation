package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type testTrustMarkRetriever struct {
	status *string
	err    error
}

func (r testTrustMarkRetriever) GetTrustMarkStatus(_ context.Context, _ string) (*string, error) {
	return r.status, r.err
}

func (r testTrustMarkRetriever) IssueTrustMark(_ context.Context, _ string, _ model.EntityIdentifier) (*string, error) {
	return nil, nil
}

func (r testTrustMarkRetriever) ListTrustMarks(_ context.Context, _ string, _ *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	return nil, nil
}

func startTrustMarkStatusServer(t *testing.T, retriever model.TrustMarkRetriever) *httptest.Server {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("expected no error creating signer, got %q", err.Error())
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("expected no error creating public JWK, got %q", err.Error())
	}

	server := NewServer(model.ServerConfiguration{
		EntityIdentifier: "https://issuer.example.com",
		SignerConfiguration: model.SignerConfiguration{
			Algorithm: "ES256",
			Signer:    signer,
			KeyID:     (*publicJWK)["kid"].(string),
		},
		TrustMarkRetriever: retriever,
	})
	m := http.NewServeMux()
	server.Configure(m)
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	return s
}

func TestServer_TrustMarkStatus(t *testing.T) {
	s := startTrustMarkStatusServer(t, testTrustMarkRetriever{status: model.Pointer("active")})

	form := url.Values{"trust_mark": {"a.b.c"}}
	resp, err := s.Client().Post(s.URL+"/trust-mark-status", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/trust-mark-status-response+jwt" {
		t.Errorf("expected trust-mark-status-response+jwt content type, got %q", ct)
	}

	claims := decodeJWTClaims(t, resp)
	if claims["status"] != "active" {
		t.Errorf("expected status 'active', got %v", claims["status"])
	}
	if claims["trust_mark"] != "a.b.c" {
		t.Errorf("expected trust_mark echoed back, got %v", claims["trust_mark"])
	}
	if claims["iss"] != "https://issuer.example.com" {
		t.Errorf("expected iss to be the issuer, got %v", claims["iss"])
	}
}

func TestServer_TrustMarkStatus_MissingTrustMark(t *testing.T) {
	s := startTrustMarkStatusServer(t, testTrustMarkRetriever{status: model.Pointer("active")})

	resp, err := s.Client().Post(s.URL+"/trust-mark-status", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	validateErrorResponse(t, resp, nil, http.StatusBadRequest, "invalid_request", "request missing required parameter 'trust_mark'")
}

func TestServer_TrustMarkStatus_RejectsGet(t *testing.T) {
	s := startTrustMarkStatusServer(t, testTrustMarkRetriever{status: model.Pointer("active")})

	resp, err := s.Client().Get(s.URL + "/trust-mark-status?trust_mark=a.b.c")
	if err != nil {
		t.Fatalf("expected no error, got %q", err.Error())
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for GET, got %d", resp.StatusCode)
	}
}

func decodeJWTClaims(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("expected no error reading body, got %q", err.Error())
	}
	parts := strings.Split(string(body), ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("expected no error decoding payload, got %q", err.Error())
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("expected no error parsing payload, got %q", err.Error())
	}
	return claims
}
