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
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_ATrustAnchorResolvesAsItsOwnSubject(t *testing.T) {
	anchorSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the anchor signer: %v", err)
	}
	otherSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a second signer: %v", err)
	}
	keySet := func(t *testing.T, signer josemodel.Signer) josemodel.Jwks {
		public, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("failed to read a public key: %v", err)
		}
		(*public)["kid"] = "ta"
		return josemodel.Jwks{Keys: []map[string]any{*public}}
	}

	tests := []struct {
		name      string
		reference string
		anchors   func(anchor model.EntityIdentifier) map[model.EntityIdentifier]josemodel.Jwks
		status    int
		code      string
	}{
		{
			name:      "with no anchor keys held",
			reference: "10.2",
			anchors:   func(model.EntityIdentifier) map[model.EntityIdentifier]josemodel.Jwks { return nil },
			status:    http.StatusOK,
		},
		{
			name:      "with the anchor's own key held",
			reference: "10.2",
			anchors: func(anchor model.EntityIdentifier) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{anchor: keySet(t, anchorSigner)}
			},
			status: http.StatusOK,
		},
		{
			name:      "with a different key held for the anchor",
			reference: "10.2",
			anchors: func(anchor model.EntityIdentifier) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{anchor: keySet(t, otherSigner)}
			},
			status: http.StatusNotFound,
			code:   model.InvalidTrustAnchor,
		},
		{
			name:      "with keys held only for another anchor",
			reference: "8.9",
			anchors: func(model.EntityIdentifier) map[model.EntityIdentifier]josemodel.Jwks {
				return map[model.EntityIdentifier]josemodel.Jwks{"https://other-ta.example.com": keySet(t, anchorSigner)}
			},
			status: http.StatusNotFound,
			code:   model.InvalidTrustAnchor,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: anchorSigner, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
			})
			mux := http.NewServeMux()
			s.Configure(mux)
			ts := httptest.NewTLSServer(mux)
			t.Cleanup(ts.Close)
			anchor := model.EntityIdentifier(ts.URL)
			s.SetEntityIdentifier(anchor)
			s.SetHttpClient(ts.Client())
			s.cfg.TrustAnchors = tc.anchors(anchor)

			response, err := ts.Client().Get(ts.URL + "/resolve?sub=" + ts.URL + "&trust_anchor=" + ts.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("[%s] expected %d, got %d %s", tc.reference, tc.status, response.StatusCode, raw)
			}
			if tc.code != "" {
				var answer map[string]string
				if err := json.Unmarshal(raw, &answer); err != nil {
					t.Fatalf("failed to read the error: %v", err)
				}
				if answer["error"] != tc.code {
					t.Errorf("[%s] expected %s, got %s", tc.reference, tc.code, raw)
				}
				return
			}

			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(string(raw), ".")[1])
			if err != nil {
				t.Fatalf("failed to decode the resolve response: %v", err)
			}
			var resolved struct {
				Sub        string         `json:"sub"`
				TrustChain []string       `json:"trust_chain"`
				Metadata   map[string]any `json:"metadata"`
			}
			if err := json.Unmarshal(payload, &resolved); err != nil {
				t.Fatalf("failed to read the resolve response: %v", err)
			}
			if resolved.Sub != ts.URL {
				t.Errorf("[8.3.2] expected the response to be about the trust anchor, got sub %q", resolved.Sub)
			}
			if len(resolved.TrustChain) != 1 {
				t.Fatalf("[8.3.2] expected a trust chain of the anchor's own entity configuration alone, got %d entries", len(resolved.TrustChain))
			}
			entry, err := base64.RawURLEncoding.DecodeString(strings.Split(resolved.TrustChain[0], ".")[1])
			if err != nil {
				t.Fatalf("failed to decode the chain entry: %v", err)
			}
			var statement struct {
				Iss string `json:"iss"`
				Sub string `json:"sub"`
			}
			if err := json.Unmarshal(entry, &statement); err != nil {
				t.Fatalf("failed to read the chain entry: %v", err)
			}
			if statement.Iss != ts.URL || statement.Sub != ts.URL {
				t.Errorf("[10.2] expected the entry to be the anchor's entity configuration, got iss %q sub %q", statement.Iss, statement.Sub)
			}
			if _, ok := resolved.Metadata["federation_entity"]; !ok {
				t.Errorf("[6.1.4] with no subordinate statements the resolved metadata is the anchor's own, got %v", resolved.Metadata)
			}
		})
	}
}
