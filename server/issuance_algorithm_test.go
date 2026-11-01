package server

import (
	"bytes"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

var unsignableAlgorithms = map[string]string{
	"EdDSA":  "sign with Ed25519",
	"HS256":  "a symmetric key would not be secret",
	"HS384":  "a symmetric key would not be secret",
	"HS512":  "a symmetric key would not be secret",
	"es256":  "is not a supported signing algorithm",
	"RS256 ": "is not a supported signing algorithm",
	"none":   "is not a supported signing algorithm",
}

func TestNew_RefusesASigningAlgorithmByName(t *testing.T) {
	for algorithm, expect := range unsignableAlgorithms {
		t.Run(algorithm, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			_, err = entity_configuration.New(t.Context(), model.ServerConfiguration{
				EntityIdentifier:            "https://issuer.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: algorithm, Signer: signer, KeyID: "issuer-key"},
				EntityConfigurationLifetime: time.Hour,
			})
			if err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("[3.2 step 3] expected issuance to refuse %q naming %q, got %v", algorithm, expect, err)
			}
		})
	}
}

func TestServer_ASignedResponseIsNotIssuedUnderAnAlgorithmThisLibraryCannotSignWith(t *testing.T) {
	type endpoint struct {
		description string
		request     func(t *testing.T, algorithm string, logs *bytes.Buffer) *http.Response
	}
	endpoints := map[string]endpoint{
		"/subordinate-status": {description: subordinateStatusUnavailableError, request: func(t *testing.T, algorithm string, logs *bytes.Buffer) *http.Response {
			ts := contractServer(t, func(cfg *model.ServerConfiguration) {
				cfg.SignerConfiguration.Algorithm = algorithm
				cfg.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				cfg.Extensions = model.Extensions{SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: sharedStatusRetriever{shared: &model.SubordinateStatusResponse{}}}}
			})
			return get(t, ts, "/subordinate-status?sub="+url.QueryEscape("https://leaf.example.com"))
		}},
		"/trust-mark-status": {description: trustMarkStatusUnavailableError, request: func(t *testing.T, algorithm string, logs *bytes.Buffer) *http.Response {
			ts := contractServer(t, func(cfg *model.ServerConfiguration) {
				cfg.SignerConfiguration.Algorithm = algorithm
				cfg.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				cfg.TrustMarkRetriever = testTrustMarkRetriever{status: model.Pointer("active")}
			})
			response, err := ts.Client().Post(ts.URL+"/trust-mark-status", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"trust_mark": {"a.b.c"}}.Encode()))
			if err != nil {
				t.Fatalf("the handler did not answer: %v", err)
			}
			return response
		}},
		"/resolve": {description: resolveUnavailableError, request: func(t *testing.T, algorithm string, logs *bytes.Buffer) *http.Response {
			var peer *peerFederation
			peer = startPeerFederation(t, func(base string) map[string]any {
				return federationFetchEndpointMetadata(base + "/fetch")
			}, func(w http.ResponseWriter, r *http.Request) {
				base := "https://" + r.Host
				writePeerStatement(w, peer.signer, map[string]any{
					"iss": base + "/anchor", "sub": base + "/leaf",
					"iat": time.Now().Add(-time.Minute).UTC().Unix(), "exp": time.Now().Add(10 * time.Minute).UTC().Unix(),
					"jwks": map[string]any{"keys": []any{peer.publicJWK}},
				})
			})
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			resolver := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: algorithm, Signer: signer, KeyID: "resolver"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: 10 * time.Minute},
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))},
			})
			mux := http.NewServeMux()
			resolver.Configure(mux)
			resolverServer := httptest.NewTLSServer(mux)
			t.Cleanup(resolverServer.Close)
			resolver.SetEntityIdentifier(model.EntityIdentifier(resolverServer.URL))
			resolver.SetHttpClient(peer.server.Client())
			return get(t, resolverServer, "/resolve?sub="+url.QueryEscape(peer.leafID)+"&trust_anchor="+url.QueryEscape(peer.anchorID))
		}},
	}

	for name, e := range endpoints {
		t.Run(name, func(t *testing.T) {
			control := e.request(t, "ES256", &bytes.Buffer{})
			_ = control.Body.Close()
			if control.StatusCode != http.StatusOK {
				t.Fatalf("the fixture is wrong: with ES256 %s answered %d", name, control.StatusCode)
			}
			for algorithm := range unsignableAlgorithms {
				t.Run(algorithm, func(t *testing.T) {
					var logs bytes.Buffer
					response := e.request(t, algorithm, &logs)
					defer response.Body.Close() //nolint:errcheck
					raw, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatalf("failed to read the response: %v", err)
					}
					if response.StatusCode != http.StatusInternalServerError || !strings.Contains(string(raw), `"`+model.ServerError+`"`) {
						t.Errorf("[8.9] a signing algorithm this server cannot sign with is its own fault, got %d with %s", response.StatusCode, raw)
					}
					if !strings.Contains(string(raw), e.description) {
						t.Errorf("expected the fixed description %q, got %s", e.description, raw)
					}
					if !strings.Contains(logs.String(), "the configured signing algorithm cannot be signed with") || !strings.Contains(logs.String(), unsignableAlgorithms[algorithm]) {
						t.Errorf("an operator must be told which setting is wrong and why, got logs %s", logs.String())
					}
				})
			}
		})
	}
}

func TestNew_DoesNotPublishASubordinateSignerKeyUnderAnAlgorithmItCannotSignWith(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	subordinateSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the subordinate signer: %v", err)
	}
	intermediate := &model.IntermediateConfiguration{SubordinateCacheTime: time.Minute}
	subordinate := leafSubordinate(t)
	subordinate.SignerConfiguration = &model.SignerConfiguration{Algorithm: "EdDSA", Signer: subordinateSigner, KeyID: "per-subordinate"}
	intermediate.AddSubordinate("https://leaf.example.com", subordinate)

	var logs bytes.Buffer
	cfg := model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   intermediate,
		Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))},
	}

	token, err := entity_configuration.New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("one unusable subordinate signer must not take down the authority's entity configuration, got %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(*token, ".")[1])
	if err != nil {
		t.Fatalf("failed to read the issued statement: %v", err)
	}
	payload := string(raw)
	if strings.Contains(payload, "per-subordinate") {
		t.Errorf("a subordinate signer key published under EdDSA would sign statements no resolver can verify, got %s", payload)
	}
	if !strings.Contains(logs.String(), "not publishing a subordinate signer key because its algorithm cannot be signed with") {
		t.Errorf("an operator must be told the key was left out, got logs %s", logs.String())
	}
}
