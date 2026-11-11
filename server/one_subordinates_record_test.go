package server

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

const (
	goodSubordinate = "https://good.example.com"
	badSubordinate  = "https://bad.example.com"
)

type recordStore map[model.EntityIdentifier]*model.SubordinateConfiguration

func (s recordStore) GetSubordinate(_ context.Context, identifier model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	if record, ok := s[identifier]; ok {
		return record, nil
	}
	return nil, model.NewNotFoundError("unknown entity identifier")
}

func (s recordStore) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return s, nil
}

func (s recordStore) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	var signers []model.SignerConfiguration
	for _, record := range s {
		if record.SignerConfiguration != nil {
			signers = append(signers, *record.SignerConfiguration)
		}
	}
	return signers, nil
}

type twoEntityListing struct{}

func (twoEntityListing) GetExtendedSubordinates(context.Context, model.ExtendedListingFilter) (*model.ExtendedListingResponse, error) {
	return &model.ExtendedListingResponse{
		ImmediateSubordinateEntities: []map[string]any{{"id": goodSubordinate}, {"id": badSubordinate}},
	}, nil
}

type refusesEveryPolicy struct{}

func (refusesEveryPolicy) Identifier() string                  { return "x_refusing_type" }
func (refusesEveryPolicy) VerifyMetadata(map[string]any) error { return nil }
func (refusesEveryPolicy) VerifyMetadataPolicy(map[string]model.PolicyOperators) error {
	return errors.New("this deployment refuses every policy for this type")
}
func (refusesEveryPolicy) VerifyResolvedMetadata(map[string]any) error { return nil }

type unconvertibleKeySigner struct{ crypto.Signer }

func (unconvertibleKeySigner) Public() crypto.PublicKey { return struct{}{} }

type otherKeySigner struct {
	josemodel.Signer
	public crypto.PublicKey
}

func (o otherKeySigner) Public() crypto.PublicKey { return o.public }

func TestServer_OneSubordinatesRecordDoesNotTakeDownWhatServesTheOthers(t *testing.T) {
	newKey := func(t *testing.T, kid string) (josemodel.Signer, map[string]any) {
		t.Helper()
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a signer: %v", err)
		}
		public, err := jwk.PublicJwk(signer.Public())
		if err != nil {
			t.Fatalf("failed to read a public key: %v", err)
		}
		(*public)["kid"] = kid
		return signer, *public
	}
	withPolicy := func(t *testing.T, raw string) *model.SubordinateConfiguration {
		t.Helper()
		_, key := newKey(t, "bad")
		var policy model.MetadataPolicy
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			t.Fatalf("failed to build the policy: %v", err)
		}
		return &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{key}}, Policies: policy}
	}
	withKid := func(key map[string]any, kid any) map[string]any {
		copied := map[string]any{}
		for member, value := range key {
			copied[member] = value
		}
		if kid == nil {
			delete(copied, "kid")
		} else {
			copied["kid"] = kid
		}
		return copied
	}

	tests := []struct {
		name        string
		entityTypes model.EntityTypeRegistry
		record      func(t *testing.T) *model.SubordinateConfiguration
	}{
		{
			name: "a record registered with no keys",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				return &model.SubordinateConfiguration{}
			},
		},
		{
			name: "a record whose key has no kid",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{withKid(key, nil)}}}
			},
		},
		{
			name: "a record whose kid is not a string",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{withKid(key, 7)}}}
			},
		},
		{
			name: "a record with two keys under one kid",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, first := newKey(t, "bad")
				_, second := newKey(t, "bad")
				return &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: []map[string]any{first, second}}}
			},
		},
		{
			name: "a record whose policy holds an operator this library does not understand",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{
					JWKs:     josemodel.Jwks{Keys: []map[string]any{key}},
					Policies: model.MetadataPolicy{FederationMetadata: map[string]model.PolicyOperators{"organization_name": {Unrecognised: []string{"not_an_operator"}}}},
				}
			},
		},
		{
			name: "a record whose policy would publish a private key",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				return withPolicy(t, `{"openid_relying_party":{"jwks":{"value":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cLvhgLlb8TXx0cfw3xQk9Q","kid":"p"}]}}}}`)
			},
		},
		{
			name:        "a record whose policy the deployment's own entity type refuses",
			entityTypes: model.EntityTypeRegistry{"x_refusing_type": refusesEveryPolicy{}},
			record: func(t *testing.T) *model.SubordinateConfiguration {
				return withPolicy(t, `{"x_refusing_type":{"p":{"value":"a"}}}`)
			},
		},
		{
			name: "a record whose policy sets a built-in entity type through Extensions",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, key := newKey(t, "bad")
				var pinned model.PolicyOperators
				if err := json.Unmarshal([]byte(`{"value":"Pinned"}`), &pinned); err != nil {
					t.Fatalf("failed to build the policy: %v", err)
				}
				return &model.SubordinateConfiguration{
					JWKs:     josemodel.Jwks{Keys: []map[string]any{key}},
					Policies: model.MetadataPolicy{Extensions: map[string]map[string]model.PolicyOperators{"federation_entity": {"organization_name": pinned}}},
				}
			},
		},
		{
			name: "a record with its own signer under an empty key id",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				signer, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{
					JWKs:                josemodel.Jwks{Keys: []map[string]any{key}},
					SignerConfiguration: &model.SignerConfiguration{Algorithm: "ES256", Signer: signer},
				}
			},
		},
		{
			name: "a record with its own signer configuration but no signer",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{
					JWKs:                josemodel.Jwks{Keys: []map[string]any{key}},
					SignerConfiguration: &model.SignerConfiguration{Algorithm: "ES256", KeyID: "bad-signer"},
				}
			},
		},
		{
			name: "a record with its own signer under an algorithm this library does not issue with",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				signer, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{
					JWKs:                josemodel.Jwks{Keys: []map[string]any{key}},
					SignerConfiguration: &model.SignerConfiguration{Algorithm: "HS256", KeyID: "bad-signer", Signer: signer},
				}
			},
		},
		{
			name: "a record with its own RSA signer declared as ES256",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				_, key := newKey(t, "bad")
				signer, err := jws.GetSigner(jwa.RS256, nil)
				if err != nil {
					t.Fatalf("failed to build an RSA signer: %v", err)
				}
				return &model.SubordinateConfiguration{
					JWKs:                josemodel.Jwks{Keys: []map[string]any{key}},
					SignerConfiguration: &model.SignerConfiguration{Algorithm: "ES256", KeyID: "bad-signer", Signer: signer},
				}
			},
		},
		{
			name: "a record with its own signer whose signature does not verify under the key it publishes",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				signer, key := newKey(t, "bad")
				other, _ := newKey(t, "other")
				return &model.SubordinateConfiguration{
					JWKs:                josemodel.Jwks{Keys: []map[string]any{key}},
					SignerConfiguration: &model.SignerConfiguration{Algorithm: "ES256", KeyID: "bad-signer", Signer: otherKeySigner{Signer: signer, public: other.Public()}},
				}
			},
		},
		{
			name: "a record with its own signer whose public key cannot be published",
			record: func(t *testing.T) *model.SubordinateConfiguration {
				signer, key := newKey(t, "bad")
				return &model.SubordinateConfiguration{
					JWKs:                josemodel.Jwks{Keys: []map[string]any{key}},
					SignerConfiguration: &model.SignerConfiguration{Algorithm: "ES256", KeyID: "bad-signer", Signer: unconvertibleKeySigner{signer}},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authoritySigner, _ := newKey(t, "ta")
			_, goodKey := newKey(t, "good")
			logs := &lockedBuffer{}
			server := NewServer(model.ServerConfiguration{
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: authoritySigner, KeyID: "ta"},
				EntityConfigurationLifetime: time.Hour,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Hour},
				MetadataRetriever: recordStore{
					goodSubordinate: {JWKs: josemodel.Jwks{Keys: []map[string]any{goodKey}}},
					badSubordinate:  tc.record(t),
				},
				Extensions: model.Extensions{
					ExtendedListing: model.ExtendedListingConfiguration{Enabled: true, SizeLimit: 10, MetadataRetriever: twoEntityListing{}},
				},
				Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})), EntityTypes: tc.entityTypes},
			})
			mux := http.NewServeMux()
			server.Configure(mux)
			ts := httptest.NewServer(mux)
			t.Cleanup(ts.Close)

			get := func(path string) (int, string) {
				t.Helper()
				response, err := ts.Client().Get(ts.URL + path)
				if err != nil {
					t.Fatalf("the handler did not answer: %v", err)
				}
				defer response.Body.Close() //nolint:errcheck
				raw, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read the response: %v", err)
				}
				return response.StatusCode, string(raw)
			}

			if status, body := get("/.well-known/openid-federation"); status != http.StatusOK {
				t.Errorf("one subordinate's record must not take down the authority's entity configuration, got %d %s", status, body)
			}

			if status, body := get("/fetch?sub=" + url.QueryEscape(goodSubordinate)); status != http.StatusOK {
				t.Errorf("expected the good subordinate's statement, got %d %s", status, body)
			}
			status, body := get("/fetch?sub=" + url.QueryEscape(badSubordinate))
			var answer map[string]string
			if err := json.Unmarshal([]byte(body), &answer); err != nil || status != http.StatusInternalServerError || answer["error"] != model.ServerError {
				t.Errorf("[8.9] expected the bad subordinate's own statement to answer 500 server_error, got %d %s", status, body)
			}

			status, body = get("/extended-list?claims=subordinate_statement")
			if status != http.StatusOK {
				t.Fatalf("one subordinate's record must not take down the listing for the others, got %d %s", status, body)
			}
			var listing model.ExtendedListingResponse
			if err := json.Unmarshal([]byte(body), &listing); err != nil {
				t.Fatalf("failed to read the listing: %v", err)
			}
			statements := map[string]bool{}
			for _, entry := range listing.ImmediateSubordinateEntities {
				id, _ := entry["id"].(string)
				_, statements[id] = entry["subordinate_statement"]
			}
			if present, listed := statements[goodSubordinate]; !listed || !present {
				t.Errorf("expected the good subordinate listed with its statement, got %s", body)
			}
			if present, listed := statements[badSubordinate]; !listed || present {
				t.Errorf("expected the bad subordinate listed without a statement, got %s", body)
			}

			errorLines := 0
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, badSubordinate) {
					errorLines++
				}
			}
			if errorLines == 0 {
				t.Errorf("expected the operator's bad record logged at error level naming the subordinate, got %s", logs.String())
			}
		})
	}
}
