package server

import (
	"context"
	"crypto"
	"errors"
	"io"
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

type classifiedSubordinateRetriever struct{ err error }

func (r classifiedSubordinateRetriever) GetSubordinate(context.Context, model.EntityIdentifier) (*model.SubordinateConfiguration, error) {
	return nil, r.err
}

func (r classifiedSubordinateRetriever) GetSubordinates(context.Context) (map[model.EntityIdentifier]*model.SubordinateConfiguration, error) {
	return nil, nil
}

func (r classifiedSubordinateRetriever) GetSubordinateSigners(context.Context) ([]model.SignerConfiguration, error) {
	return nil, nil
}

type refusingSigner struct {
	public crypto.PublicKey
	err    error
}

func (s refusingSigner) Public() crypto.PublicKey { return s.public }

func (s refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

func startFetchServer(t *testing.T, cfg model.ServerConfiguration) *httptest.Server {
	t.Helper()
	cfg.EntityIdentifier = "https://ta.example.com"
	cfg.EntityConfiguration = model.EntityStatement{Iss: "https://ta.example.com"}
	if cfg.EntityConfigurationLifetime == 0 {
		cfg.EntityConfigurationLifetime = time.Hour
	}
	server := NewServer(cfg)
	mux := http.NewServeMux()
	server.Configure(mux)
	fetchServer := httptest.NewServer(mux)
	t.Cleanup(fetchServer.Close)
	return fetchServer
}

func TestServer_Fetch_RetrieverFailureKeepsItsErrorClass(t *testing.T) {
	tests := map[string]struct {
		reference   string
		err         error
		status      int
		code        string
		description string
	}{
		"a store that is temporarily unable to answer": {
			reference:   "8.9 temporarily_unavailable",
			err:         model.NewTemporarilyUnavailableError("database down"),
			status:      http.StatusServiceUnavailable,
			code:        model.TemporarilyUnavailable,
			description: "database down",
		},
		"a store that failed unexpectedly": {
			reference:   "8.9 server_error",
			err:         model.NewServerError("query failed"),
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: "query failed",
		},
		"a subject the store refuses to serve": {
			reference:   "8.9 invalid_subject",
			err:         model.NewInvalidSubjectError("subject not served here"),
			status:      http.StatusNotFound,
			code:        model.InvalidSubject,
			description: "subject not served here",
		},
		"a subject the store does not hold": {
			reference:   "8.9 not_found",
			err:         model.NewNotFoundError("unknown entity identifier"),
			status:      http.StatusNotFound,
			code:        model.NotFound,
			description: "unknown entity identifier",
		},
		"a store failure with no class of its own": {
			reference:   "8.9 server_error",
			err:         errors.New("pq: relation \"subordinates\" does not exist"),
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			description: subordinateRetrievalFailureError,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			publicJWK, err := jwk.PublicJwk(signer.Public())
			if err != nil {
				t.Fatalf("failed to build the public jwk: %v", err)
			}
			fetchServer := startFetchServer(t, model.ServerConfiguration{
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: (*publicJWK)["kid"].(string)},
				IntermediateConfiguration: &model.IntermediateConfiguration{SubordinateCacheTime: time.Minute},
				MetadataRetriever:         classifiedSubordinateRetriever{err: tc.err},
			})

			response, err := fetchServer.Client().Get(fetchServer.URL + "/fetch?sub=" + url.QueryEscape("https://leaf.example.com"))
			if err != nil {
				t.Fatalf("[%s] the fetch handler did not answer: %v", tc.reference, err)
			}
			validateErrorResponse(t, response, nil, tc.status, tc.code, tc.description)
		})
	}
}

func TestServer_Fetch_DoesNotReflectIssuanceFailureDetail(t *testing.T) {
	tests := map[string]struct {
		reference string
		lifetime  time.Duration
		refuse    error
		forbidden []string
	}{
		"a signer that refuses to sign": {
			reference: "8.9 server_error",
			lifetime:  time.Hour,
			refuse:    errors.New("kms: AccessDenied arn:aws:kms:eu-west-2:123456789012:key/abcd"),
			forbidden: []string{"kms", "arn:", "AccessDenied"},
		},
		"a statement lifetime this implementation refuses to publish": {
			reference: "8.9 server_error",
			lifetime:  500 * time.Millisecond,
			forbidden: []string{"SubordinateStatementLifetime", "500ms", "at least one second"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			working, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}
			subordinateJWK := distinctSubordinateKey(t)
			var signer crypto.Signer = working
			if tc.refuse != nil {
				signer = refusingSigner{public: working.Public(), err: tc.refuse}
			}

			intermediate := &model.IntermediateConfiguration{
				SubordinateCacheTime:         time.Minute,
				SubordinateStatementLifetime: tc.lifetime,
			}
			intermediate.AddSubordinate("https://leaf.example.com", &model.SubordinateConfiguration{
				JWKs: josemodel.Jwks{Keys: []map[string]any{subordinateJWK}},
			})

			fetchServer := startFetchServer(t, model.ServerConfiguration{
				SignerConfiguration:       model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "server"},
				IntermediateConfiguration: intermediate,
			})

			response, err := fetchServer.Client().Get(fetchServer.URL + "/fetch?sub=" + url.QueryEscape("https://leaf.example.com"))
			if err != nil {
				t.Fatalf("[%s] the fetch handler did not answer: %v", tc.reference, err)
			}
			defer response.Body.Close() //nolint:errcheck
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			body := string(raw)

			if response.StatusCode != http.StatusInternalServerError {
				t.Errorf("[%s] expected 500 for a failure of this server's own, got %d with %s", tc.reference, response.StatusCode, body)
			}
			if !strings.Contains(body, `"`+model.ServerError+`"`) {
				t.Errorf("[%s] expected the error code for an unexpected condition of this server, got %s", tc.reference, body)
			}
			if !strings.Contains(body, subordinateStatementUnavailableError) {
				t.Errorf("[%s] expected the fixed description %q, got %s", tc.reference, subordinateStatementUnavailableError, body)
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(body, forbidden) {
					t.Errorf("[%s] the response reveals %q about this server's own issuance failure: %s", tc.reference, forbidden, body)
				}
			}
		})
	}
}
