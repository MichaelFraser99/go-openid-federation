package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Fetch_IssuesAOneOfOnScopeAndLogsIt(t *testing.T) {
	const message = "the metadata policy configured for a subordinate puts one_of on scope"
	tests := map[string]struct {
		policy string
		logged bool
	}{
		"one_of on scope":             {policy: `{"openid_relying_party":{"scope":{"one_of":["openid"]}}}`, logged: true},
		"subset_of on scope":          {policy: `{"openid_relying_party":{"scope":{"subset_of":["openid"]}}}`},
		"one_of on another parameter": {policy: `{"openid_relying_party":{"token_endpoint_auth_method":{"one_of":["none"]}}}`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			subordinateJWK, err := jwk.PublicJwk(signer.Public())
			if err != nil {
				t.Fatalf("failed to build the public jwk: %v", err)
			}
			var policy model.MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
			intermediate := &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour}
			intermediate.AddSubordinate("https://leaf.example.com", &model.SubordinateConfiguration{
				JWKs:     josemodel.Jwks{Keys: []map[string]any{*subordinateJWK}},
				Policies: policy,
			})
			logs := &lockedBuffer{}
			fetchServer := startFetchServer(t, model.ServerConfiguration{
				Configuration:             model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: (*subordinateJWK)["kid"].(string)},
				IntermediateConfiguration: intermediate,
			})

			response, err := fetchServer.Client().Get(fetchServer.URL + "/fetch?sub=" + url.QueryEscape("https://leaf.example.com"))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("[6.1.3] expected the statement to be issued, because the spec does not refuse this policy, got %d %s", response.StatusCode, body)
			}

			var line map[string]any
			for _, raw := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				if strings.Contains(raw, message) {
					_ = json.Unmarshal([]byte(raw), &line)
				}
			}
			if logged := line != nil; logged != tc.logged {
				t.Fatalf("expected logged=%v, got %v: %s", tc.logged, logged, logs.String())
			}
			if tc.logged && (line["level"] != "ERROR" || line["subject"] != "https://leaf.example.com" || line["entity_types"] != "openid_relying_party") {
				t.Errorf("expected an Error line naming the subject and entity type, got %v", line)
			}
		})
	}
}
