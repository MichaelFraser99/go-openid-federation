package client

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
	"github.com/MichaelFraser99/go-openid-federation/server_test"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestClient_BuildTrustChain(t *testing.T) {
	testServer := server_test.TestServer(t)
	testHttpClient := testServer.Client()
	testServerURL := testServer.URL

	client := New(model.ClientConfiguration{Configuration: model.Configuration{HttpClient: testHttpClient}})
	tests := map[string]struct {
		subject, trustAnchor string
		validate             func(t *testing.T, result []model.EntityStatement, signedResult []string, expiry *int64, err error)
	}{
		"we can retrieve and validate a trust chain": {
			subject:     fmt.Sprintf("%s/leaf", testServerURL),
			trustAnchor: fmt.Sprintf("%s/ta", testServerURL),
			validate: func(t *testing.T, result []model.EntityStatement, signedResult []string, expiry *int64, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}
				if len(result) != 5 {
					t.Fatalf("expected result to be length 5, got %d", len(result))
				}
				if expiry == nil {
					t.Fatal("expected expiry to be non-nil")
				}

				earliest := result[0].Exp
				for _, statement := range result[1:] {
					earliest = min(earliest, statement.Exp)
				}
				if *expiry != earliest {
					t.Errorf("[10.4] expected the chain expiry to be the minimum exp within the chain, %d, got %d", earliest, *expiry)
				}
				if result[1].Exp >= result[0].Exp {
					t.Fatalf("the fixture is wrong: the subordinate statement about the leaf must expire before the leaf's own configuration")
				}
				if *expiry != result[1].Exp {
					t.Errorf("[10.4] expected the chain expiry to be the subordinate statement's exp, %d, got %d", result[1].Exp, *expiry)
				}
				if string(result[0].Sub) != fmt.Sprintf("%s/leaf", testServerURL) {
					t.Errorf("expected result[0].Sub to be %s, got %s", fmt.Sprintf("%s/leaf", testServerURL), result[0].Sub)
				}
				if string(result[0].Iss) != fmt.Sprintf("%s/leaf", testServerURL) {
					t.Errorf("expected result[0].Iss to be %s, got %s", fmt.Sprintf("%s/leaf", testServerURL), result[0].Iss)
				}
				if string(result[1].Sub) != fmt.Sprintf("%s/leaf", testServerURL) {
					t.Errorf("expected result[1].Sub to be %s, got %s", fmt.Sprintf("%s/leaf", testServerURL), result[1].Sub)
				}
				if string(result[1].Iss) != fmt.Sprintf("%s/int1", testServerURL) {
					t.Errorf("expected result[1].Iss to be %s, got %s", fmt.Sprintf("%s/int1", testServerURL), result[1].Iss)
				}
				if string(result[2].Sub) != fmt.Sprintf("%s/int1", testServerURL) {
					t.Errorf("expected result[2].Sub to be %s, got %s", fmt.Sprintf("%s/int1", testServerURL), result[2].Sub)
				}
				if string(result[2].Iss) != fmt.Sprintf("%s/int2", testServerURL) {
					t.Errorf("expected result[2].Iss to be %s, got %s", fmt.Sprintf("%s/int2", testServerURL), result[2].Iss)
				}
				if string(result[3].Sub) != fmt.Sprintf("%s/int2", testServerURL) {
					t.Errorf("expected result[2].Sub to be %s, got %s", fmt.Sprintf("%s/int2", testServerURL), result[2].Sub)
				}
				if string(result[3].Iss) != fmt.Sprintf("%s/ta", testServerURL) {
					t.Errorf("expected result[2].Iss to be %s, got %s", fmt.Sprintf("%s/ta", testServerURL), result[2].Iss)
				}
				if string(result[4].Sub) != fmt.Sprintf("%s/ta", testServerURL) {
					t.Errorf("expected result[2].Sub to be %s, got %s", fmt.Sprintf("%s/ta", testServerURL), result[2].Sub)
				}
				if string(result[4].Iss) != fmt.Sprintf("%s/ta", testServerURL) {
					t.Errorf("expected result[2].Iss to be %s, got %s", fmt.Sprintf("%s/ta", testServerURL), result[2].Iss)
				}
				if len(result) != len(signedResult) {
					t.Fatalf("expected signed result to have length %d, got %d", len(result), len(signedResult))
				}
				//todo: validate returned signed response - the client needs basic methods to retrieve an entity configuration / subordinate statement anyway
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			signedResult, result, exp, err := client.BuildTrustChain(t.Context(), tt.subject, tt.trustAnchor)
			tt.validate(t, result, signedResult, exp, err)
		})
	}
}

func TestClient_ResolveMetadata(t *testing.T) {
	testServer := server_test.TestServer(t)
	testHttpClient := testServer.Client()
	testServerURL := testServer.URL

	client := New(model.ClientConfiguration{Configuration: model.Configuration{HttpClient: testHttpClient}})
	tests := map[string]struct {
		subject, trustAnchor string
		validate             func(t *testing.T, result *model.Metadata, err error)
	}{
		"we can retrieve and validate a trust chain": {
			subject:     fmt.Sprintf("%s/leaf", testServerURL),
			trustAnchor: fmt.Sprintf("%s/ta", testServerURL),
			validate: func(t *testing.T, result *model.Metadata, err error) {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if result == nil {
					t.Fatal("expected result to be non-nil")
				}

				expectedMetadata := fmt.Sprintf(`
{
    "openid_provider": {
  "authorization_endpoint":
    "https://op.umu.se/openid/authorization",
  "contacts": [
    "ops@swamid.se",
    "ops@edugain.geant.org"
  ],
  "federation_registration_endpoint":
    "https://op.umu.se/openid/fedreg",
  "client_registration_types_supported": [
    "automatic",
    "explicit"
  ],
  "grant_types_supported": [
    "authorization_code",
    "implicit",
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256"
  ],
  "issuer": "%s/leaf",
  "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
  "logo_uri":
    "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
  "organization_name": "University of Umeå",
  "op_policy_uri":
    "https://www.umu.se/en/website/legal-information/",
  "request_parameter_supported": true,
  "response_types_supported": [
    "code",
    "code id_token",
    "token"
  ],
  "subject_types_supported": [
    "pairwise"
  ],
  "token_endpoint": "https://op.umu.se/openid/token",
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt",
    "client_secret_jwt"
  ]
}
}`, testServerURL)

				var expected map[string]any
				err = json.Unmarshal([]byte(expectedMetadata), &expected)
				if err != nil {
					t.Fatalf("expected valid JSON in expected metadata, got error %q", err.Error())
				}

				resultBytes, err := json.Marshal(*result)
				if err != nil {
					t.Fatalf("error marshalling result to json: %q", err.Error())
				}

				var resultMap map[string]any
				err = json.Unmarshal(resultBytes, &resultMap)
				if err != nil {
					t.Fatalf("expected valid JSON in result metadata, got error %q", err.Error())
				}

				if diff := cmp.Diff(expected, resultMap, cmpopts.SortSlices(func(x, y any) bool {
					if sx, ok := x.(string); ok {
						if sy, ok := y.(string); ok {
							return sx < sy
						}
					}
					return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
				})); diff != "" {
					t.Errorf("mismatch (-expected +got):\n%s", diff)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			chain, _, _, err := client.BuildTrustChain(t.Context(), tt.subject, tt.trustAnchor)
			if err != nil {
				t.Fatalf("expected no error, got %q", err.Error())
			}
			result, err := client.ResolveMetadata(t.Context(), tt.subject, tt.trustAnchor, chain)
			tt.validate(t, result, err)
		})
	}
}
