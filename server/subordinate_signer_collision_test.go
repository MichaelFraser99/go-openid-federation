package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type orderedSignerRetriever struct{ signers []model.SignerConfiguration }

func (r orderedSignerRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, model.NewNotFoundError("unknown entity identifier")
}

func (r orderedSignerRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return map[model.EntityIdentifier]*model.SubordinateConfiguration{}, nil
}

func (r orderedSignerRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return r.signers, nil
}

func publishedKeyMaterial(t *testing.T, signer josemodel.Signer) string {
	t.Helper()
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to read the signer's public key: %v", err)
	}
	return (*public)["x"].(string) + "." + (*public)["y"].(string)
}

func TestServer_WellKnown_ASubordinateSignerWhoseKeyIDIsTakenIsLeftOutAndTheAuthorityStillAnswers(t *testing.T) {
	const droppedLine = "not publishing a subordinate signer key because a key already published under its key ID does not match it"

	newSigner := func(t *testing.T) josemodel.Signer {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		return signer
	}
	authority := newSigner(t)
	first := newSigner(t)
	second := newSigner(t)

	tests := []struct {
		name      string
		signers   []model.SignerConfiguration
		published map[string]josemodel.Signer
		logged    bool
	}{
		{
			name: "a second subordinate signer reusing the first one's key ID",
			signers: []model.SignerConfiguration{
				{Algorithm: "ES256", Signer: first, KeyID: "shared"},
				{Algorithm: "ES256", Signer: second, KeyID: "shared"},
			},
			published: map[string]josemodel.Signer{"ta": authority, "shared": first},
			logged:    true,
		},
		{
			name: "a subordinate signer reusing the authority's own key ID",
			signers: []model.SignerConfiguration{
				{Algorithm: "ES256", Signer: first, KeyID: "subordinate"},
				{Algorithm: "ES256", Signer: second, KeyID: "ta"},
			},
			published: map[string]josemodel.Signer{"ta": authority, "subordinate": first},
			logged:    true,
		},
		{
			name: "two subordinates sharing one signer under one key ID",
			signers: []model.SignerConfiguration{
				{Algorithm: "ES256", Signer: first, KeyID: "shared"},
				{Algorithm: "ES256", Signer: first, KeyID: "shared"},
			},
			published: map[string]josemodel.Signer{"ta": authority, "shared": first},
		},
		{
			name: "a subordinate signed by the authority's own signer under its key ID",
			signers: []model.SignerConfiguration{
				{Algorithm: "ES256", Signer: authority, KeyID: "ta"},
			},
			published: map[string]josemodel.Signer{"ta": authority},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			ts := startFetchServer(t, model.ServerConfiguration{
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: authority, KeyID: "ta"},
				IntermediateConfiguration: &model.IntermediateConfiguration{},
				MetadataRetriever:         orderedSignerRetriever{signers: tc.signers},
				Configuration:             model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))},
			})

			response, err := ts.Client().Get(ts.URL + "/.well-known/openid-federation")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("[CLAUDE.md] one subordinate's signer must never take down the authority's own entity configuration, got %d %s", response.StatusCode, raw)
			}

			parts := strings.Split(string(raw), ".")
			if len(parts) != 3 {
				t.Fatalf("[3.1] expected a compact JWS, got %s", raw)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("failed to decode the entity configuration: %v", err)
			}
			var claims struct {
				JWKs struct {
					Keys []map[string]any `json:"keys"`
				} `json:"jwks"`
			}
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("failed to read the entity configuration: %v", err)
			}

			got := map[string]string{}
			for _, key := range claims.JWKs.Keys {
				kid, _ := key["kid"].(string)
				if _, repeated := got[kid]; repeated {
					t.Fatalf("[3.1.1] every key in the jwks claim must carry a unique kid, %q appears twice in %s", kid, payload)
				}
				x, _ := key["x"].(string)
				y, _ := key["y"].(string)
				got[kid] = x + "." + y
			}
			if len(got) != len(tc.published) {
				t.Errorf("[3.1.1] expected the published keys %v, got %s", keyIDs(tc.published), payload)
			}
			for kid, signer := range tc.published {
				if got[kid] != publishedKeyMaterial(t, signer) {
					t.Errorf("[3.1.1] expected %q published with the key of the signer that first claimed it, got %s", kid, payload)
				}
			}

			if tc.logged && !loggedAtError(t, logs.String(), droppedLine) {
				t.Errorf("[CLAUDE.md] an operator must be told at Error that the key was left out, got logs %s", logs.String())
			}
			if !tc.logged && loggedAtError(t, logs.String(), "") {
				t.Errorf("[CLAUDE.md] a key ID already published for the same key must be accepted without an Error, got logs %s", logs.String())
			}
		})
	}
}

func keyIDs(published map[string]josemodel.Signer) []string {
	kids := make([]string, 0, len(published))
	for kid := range published {
		kids = append(kids, kid)
	}
	return kids
}

func loggedAtError(t *testing.T, logs, message string) bool {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}
		var record struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("failed to read a log line %q: %v", line, err)
		}
		if record.Level == slog.LevelError.String() && strings.HasPrefix(record.Msg, message) {
			return true
		}
	}
	return false
}
