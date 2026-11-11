package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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

func TestServer_ExtendedList_TheAuthoritysOwnSignerFaultFailsThePage(t *testing.T) {
	ecSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	other, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	rsaSigner, err := jws.GetSigner(jwa.RS256, nil)
	if err != nil {
		t.Fatalf("failed to build an RSA signer: %v", err)
	}

	tests := map[string]model.SignerConfiguration{
		"an RSA signer declared as ES256":                                     {Algorithm: "ES256", KeyID: "ta", Signer: rsaSigner},
		"a signer whose signature does not verify under the key it publishes": {Algorithm: "ES256", KeyID: "ta", Signer: otherKeySigner{Signer: ecSigner, public: other.Public()}},
		"a signer that cannot sign":                                           {Algorithm: "ES256", KeyID: "ta", Signer: refusingSigner{public: ecSigner.Public(), err: errors.New("the key store refused to sign")}},
	}

	for name, authoritySigner := range tests {
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuffer{}
			subordinateSigner, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			public, err := jwk.PublicJwk(subordinateSigner.Public())
			if err != nil {
				t.Fatalf("failed to read a public key: %v", err)
			}
			(*public)["kid"] = "good"
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         authoritySigner,
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				MetadataRetriever:           recordStore{goodSubordinate: {JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}}},
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: twoEntityListing{}},
				},
				Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, nil))},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}
			var answer map[string]string
			if err := json.Unmarshal(raw, &answer); err != nil || response.StatusCode != http.StatusInternalServerError || answer["error"] != model.ServerError {
				t.Errorf("[8.9 server_error] the authority's own signer fails every record alike, so the page must answer 500, not a listing with every statement left out, got %d %s", response.StatusCode, raw)
			}
			named := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, `"msg":"error creating subordinate statement"`) && strings.Contains(line, goodSubordinate) {
					named = true
				}
			}
			if !named {
				t.Errorf("expected the failure logged at error level naming the subordinate whose statement was being built, got %s", logs.String())
			}
			if name == "a signer that cannot sign" && !strings.Contains(logs.String(), `"msg":"the signer could not sign the subordinate statement","sub":"`+goodSubordinate) {
				t.Errorf("expected the signing failure to name the subordinate, got %s", logs.String())
			}
		})
	}
}

func TestServer_ExtendedList_AThrottledSignerFailsThePageEvenWhenTheRecordSuppliedIt(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	subordinateSigner, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	public, err := jwk.PublicJwk(subordinateSigner.Public())
	if err != nil {
		t.Fatalf("failed to read a public key: %v", err)
	}
	(*public)["kid"] = "good"
	throttled := &model.SignerConfiguration{Algorithm: "ES256", KeyID: "own-signer", Signer: refusingSigner{public: subordinateSigner.Public(), err: model.NewTemporarilyUnavailableError("the key store is throttling requests")}}
	server := NewServer(model.ServerConfiguration{
		EntityIdentifier:            "https://ta.example.com",
		SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", KeyID: "ta", Signer: signer},
		EntityConfigurationLifetime: time.Hour,
		IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
		MetadataRetriever:           recordStore{goodSubordinate: {JWKs: josemodel.Jwks{Keys: []map[string]any{*public}}, SignerConfiguration: throttled}},
		Extensions: model.Extensions{
			ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: twoEntityListing{}},
		},
		Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil))},
	})
	mux := http.NewServeMux()
	server.Configure(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	response, err := ts.Client().Get(ts.URL + "/extended-list?claims=subordinate_statement")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response: %v", err)
	}
	var answer map[string]string
	if err := json.Unmarshal(raw, &answer); err != nil || response.StatusCode != http.StatusServiceUnavailable || answer["error"] != model.TemporarilyUnavailable {
		t.Errorf("[8.9 temporarily_unavailable] a throttle usually comes from a key store every signer shares, so the page must answer 503, not a listing with the statement left out, got %d %s", response.StatusCode, raw)
	}
}
