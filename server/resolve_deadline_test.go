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

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const deadlineTrustMarkType = "https://ta.example.com/trust-marks/member"

func slowTrustMarkFederation(t *testing.T, delays map[string]time.Duration) *httptest.Server {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the federation signer: %v", err)
	}
	publicJWK, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build the federation jwk: %v", err)
	}
	(*publicJWK)["kid"] = "federation"
	jwks := map[string]any{"keys": []any{*publicJWK}}

	sign := func(typ string, body map[string]any) string {
		token, err := jwt.New(signer, map[string]any{"kid": "federation", "typ": typ, "alg": "ES256"}, body, jwt.Opts{Algorithm: jwa.ES256})
		if err != nil {
			t.Errorf("failed to sign a federation token: %v", err)
			return ""
		}
		return *token
	}

	var base string
	federation := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, wellKnown := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/.well-known/openid-federation")
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delays[name]):
		}

		leaf, anchor, issuer := base+"/leaf", base+"/ta", base+"/issuer"
		now := time.Now().UTC()
		statement := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": jwks}
		switch {
		case wellKnown && name == "leaf":
			statement["iss"], statement["sub"], statement["authority_hints"] = leaf, leaf, []any{anchor}
			statement["trust_marks"] = []any{map[string]any{
				"trust_mark_type": deadlineTrustMarkType,
				"trust_mark": sign("trust-mark+jwt", map[string]any{
					"iss": issuer, "sub": leaf, "trust_mark_type": deadlineTrustMarkType, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				}),
			}}
		case wellKnown && name == "issuer":
			statement["iss"], statement["sub"], statement["authority_hints"] = issuer, issuer, []any{anchor}
		case wellKnown && name == "ta":
			statement["iss"], statement["sub"] = anchor, anchor
			statement["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": anchor + "/fetch"}}
			statement["trust_mark_issuers"] = map[string]any{deadlineTrustMarkType: []any{issuer}}
		case r.URL.Path == "/ta/fetch":
			statement["iss"], statement["sub"] = anchor, r.URL.Query().Get("sub")
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(sign("entity-statement+jwt", statement)))
	}))
	t.Cleanup(federation.Close)
	base = federation.URL
	return federation
}

func resolveResponseTrustMarks(t *testing.T, token []byte) []any {
	t.Helper()
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		t.Fatalf("expected a signed resolve response, got %s", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the resolve response body: %v", err)
	}
	var body map[string]any
	if err = json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("failed to parse the resolve response body: %v", err)
	}
	marks, _ := body["trust_marks"].([]any)
	return marks
}

func TestServer_Resolve_TheWholeRequestIsBoundedByOneDeadline(t *testing.T) {
	tests := []struct {
		name     string
		deadline time.Duration
		delays   map[string]time.Duration
		complete bool
	}{
		{
			name:     "a request that completes within its deadline",
			deadline: 5 * time.Second,
			complete: true,
		},
		{
			name:     "the subject's walk outlasts the deadline",
			deadline: 300 * time.Millisecond,
			delays:   map[string]time.Duration{"leaf": 5 * time.Second},
		},
		{
			name:     "the trust mark issuer's walk outlasts the deadline",
			deadline: 300 * time.Millisecond,
			delays:   map[string]time.Duration{"issuer": 5 * time.Second},
		},
		{
			name:     "the subject's and the trust mark issuer's walks together outlast the deadline",
			deadline: time.Second,
			delays:   map[string]time.Duration{"leaf": 600 * time.Millisecond, "issuer": 600 * time.Millisecond},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			federation := slowTrustMarkFederation(t, tc.delays)

			resolverSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the resolver signer: %v", err)
			}
			resolver := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: resolverSigner, KeyID: "resolver"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
				Configuration: model.Configuration{
					MaxResolveTime:      tc.deadline,
					MaxPeerResponseTime: 10 * time.Second,
				},
			})
			mux := http.NewServeMux()
			resolver.Configure(mux)
			resolverServer := httptest.NewTLSServer(mux)
			t.Cleanup(resolverServer.Close)
			resolver.SetEntityIdentifier(model.EntityIdentifier(resolverServer.URL))
			resolver.SetHttpClient(federation.Client())

			started := time.Now()
			response, err := resolverServer.Client().Get(resolverServer.URL + "/resolve?sub=" + federation.URL + "/leaf&trust_anchor=" + federation.URL + "/ta")
			if err != nil {
				t.Fatalf("the resolve handler did not answer: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			raw, err := io.ReadAll(response.Body)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}

			if tc.complete {
				if response.StatusCode != http.StatusOK {
					t.Fatalf("[8.3.2] expected the resolve to complete, got %d with %s", response.StatusCode, model.TruncateForResponse(string(raw)))
				}
				if marks := resolveResponseTrustMarks(t, raw); len(marks) != 1 {
					t.Errorf("[8.3.2] the fixture is wrong: expected the verified trust mark in the response, got %v", marks)
				}
				return
			}

			if response.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("[8.9] this server not completing its own request within its deadline is a 503, got %d with %s", response.StatusCode, model.TruncateForResponse(string(raw)))
			}
			if !strings.Contains(string(raw), `"`+model.TemporarilyUnavailable+`"`) {
				t.Errorf("[8.9] expected the temporarily_unavailable error code, got %s", model.TruncateForResponse(string(raw)))
			}
			if elapsed < tc.deadline {
				t.Errorf("expected the request to run until its deadline of %s, it ended after %s", tc.deadline, elapsed)
			}
			if elapsed > tc.deadline+1500*time.Millisecond {
				t.Errorf("expected the request to end near its deadline of %s, it took %s", tc.deadline, elapsed)
			}
		})
	}
}
