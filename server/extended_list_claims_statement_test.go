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

func TestServer_ExtendedList_ASubordinateStatementIsReturnedOnlyWhenClaimsAllowsIt(t *testing.T) {
	const (
		registered   = "https://registered.example.com"
		unregistered = "https://unregistered.example.com"
		supplied     = "retriever.supplied.statement"
	)

	tests := []struct {
		name         string
		query        string
		subject      string
		unmarshaling bool
		want         string
	}{
		{name: "no claims parameter, which no clause governs", query: "", subject: registered, want: "supplied"},
		{name: "claims naming another claim", query: "?claims=trust_marks", subject: registered, want: "absent"},
		{name: "claims naming two other claims", query: "?claims=trust_marks,registered", subject: registered, want: "absent"},
		{name: "claims present and empty", query: "?claims=", subject: registered, want: "absent"},
		{name: "claims naming another claim twice over", query: "?claims=trust_marks&claims=metadata", subject: registered, want: "absent"},
		{name: "claims naming the statement", query: "?claims=subordinate_statement", subject: registered, want: "issued"},
		{name: "claims naming the statement and another claim", query: "?claims=trust_marks,subordinate_statement", subject: registered, want: "issued"},
		{name: "claims naming the statement for an entity this server cannot issue for", query: "?claims=subordinate_statement", subject: unregistered, want: "absent"},
		{name: "no claims parameter, for an entity this server cannot issue for", query: "", subject: unregistered, want: "supplied"},
		{name: "claims naming another claim, with a supplied statement that cannot be serialised", query: "?claims=trust_marks", subject: registered, unmarshaling: true, want: "absent"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			var statement any = supplied
			if tc.unmarshaling {
				statement = func() {}
			}
			entities := []map[string]any{{"id": tc.subject, "subordinate_statement": statement, "registered": 1}}
			server := NewServer(model.ServerConfiguration{
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: shapedExtendedRetriever{entities: entities}},
				},
			})
			subordinateSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a subordinate key: %v", err)
			}
			public, err := jwk.PublicJwk(subordinateSigner.Public())
			if err != nil {
				t.Fatalf("failed to read a subordinate key: %v", err)
			}
			(*public)["kid"] = "sub"
			server.cfg.IntermediateConfiguration.AddSubordinate(registered, &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewTLSServer(mux)
			defer ts.Close()
			server.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
			server.SetHttpClient(ts.Client())

			response, err := ts.Client().Get(ts.URL + "/extended-list" + tc.query)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d %s", response.StatusCode, raw)
			}
			var body struct {
				Entities []map[string]any `json:"immediate_subordinate_entities"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("failed to read the listing: %v", err)
			}
			if len(body.Entities) != 1 {
				t.Fatalf("expected the entry listed, got %s", raw)
			}
			entry := body.Entities[0]
			if entry["registered"] != float64(1) {
				t.Errorf("expected the entry's other claims kept, got %v", entry)
			}
			got, present := entry["subordinate_statement"]
			switch tc.want {
			case "absent":
				if present {
					t.Errorf("[Table 4] expected no subordinate_statement, which MUST NOT be returned when claims is present without it or is not this server's own, got %v", got)
				}
			case "supplied":
				if got != supplied {
					t.Errorf("expected the retriever's statement passed through when claims is absent, got %v", got)
				}
			case "issued":
				token, _ := got.(string)
				parts := strings.Split(token, ".")
				if len(parts) != 3 || token == supplied {
					t.Fatalf("[Table 4] expected the statement this server issues, got %v", got)
				}
				payload, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatalf("failed to decode the statement: %v", err)
				}
				var claims map[string]any
				if err := json.Unmarshal(payload, &claims); err != nil {
					t.Fatalf("failed to read the statement: %v", err)
				}
				if claims["iss"] != ts.URL || claims["sub"] != tc.subject {
					t.Errorf("[Table 4] expected a statement issued by this server about %s, got iss %v sub %v", tc.subject, claims["iss"], claims["sub"])
				}
			}
			if _, kept := entities[0]["subordinate_statement"]; !kept {
				t.Error("expected the retriever's own entry left as it was, not written into")
			}
		})
	}
}
