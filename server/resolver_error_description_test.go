package server

import (
	"context"
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
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const resolverFaultMarker = "dial tcp 10.0.0.7:5432 as federation_admin"

type failingResolver struct {
	err    error
	failOn model.EntityIdentifierParam
}

func (r failingResolver) ResolveEntityIdentifier(_ context.Context, param model.EntityIdentifierParam, raw string) (*model.EntityIdentifier, error) {
	if param != r.failOn {
		identifier := model.EntityIdentifier(raw)
		return &identifier, nil
	}
	return nil, r.err
}

type unreachedTrustMarkRetriever struct{ model.TrustMarkRetriever }

type unreachedSubordinateStatusRetriever struct {
	model.SubordinateStatusRetriever
}

func TestServer_AnUnclassifiedResolverErrorAnswersTheEndpointsFixedDescription(t *testing.T) {
	const subject = "https://leaf.example.com"
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	resolve := "/resolve?sub=" + url.QueryEscape(subject) + "&trust_anchor=" + url.QueryEscape("https://ta.example.com")
	endpoints := []struct {
		path        string
		failOn      model.EntityIdentifierParam
		description string
	}{
		{path: "/fetch?sub=" + url.QueryEscape(subject), failOn: model.EntityIdentifierParamSub, description: subordinateStatementUnavailableError},
		{path: resolve, failOn: model.EntityIdentifierParamSub, description: resolveUnavailableError},
		{path: resolve, failOn: model.EntityIdentifierParamTrustAnchor, description: resolveUnavailableError},
		{path: "/trust-mark?sub=" + url.QueryEscape(subject) + "&trust_mark_type=" + url.QueryEscape("https://tm.example.com"), failOn: model.EntityIdentifierParamSub, description: trustMarkUnavailableError},
		{path: "/trust-mark-list?sub=" + url.QueryEscape(subject) + "&trust_mark_type=" + url.QueryEscape("https://tm.example.com"), failOn: model.EntityIdentifierParamSub, description: trustMarkListingUnavailableError},
		{path: "/subordinate-status?sub=" + url.QueryEscape(subject), failOn: model.EntityIdentifierParamSub, description: subordinateStatusUnavailableError},
	}
	failures := []struct {
		name        string
		reference   string
		err         error
		status      int
		code        string
		description string
		errorLogged bool
	}{
		{
			name:        "an unclassified error",
			reference:   "8.9 server_error",
			err:         errors.New(resolverFaultMarker),
			status:      http.StatusInternalServerError,
			code:        model.ServerError,
			errorLogged: true,
		},
		{
			name:        "an error the resolver classified as an invalid request",
			reference:   "8.9 invalid_request",
			err:         model.NewInvalidRequestError("the alias is not one this deployment knows"),
			status:      http.StatusBadRequest,
			code:        model.InvalidRequest,
			description: "the alias is not one this deployment knows",
		},
		{
			name:        "an error the resolver classified as temporarily unavailable",
			reference:   "8.9 temporarily_unavailable",
			err:         model.NewTemporarilyUnavailableError("the alias directory is being rebuilt"),
			status:      http.StatusServiceUnavailable,
			code:        model.TemporarilyUnavailable,
		},
	}

	for _, endpoint := range endpoints {
		for _, failure := range failures {
			t.Run(strings.SplitN(endpoint.path, "?", 2)[0]+" refusing "+string(endpoint.failOn)+" with "+failure.name, func(t *testing.T) {
				logs := &lockedBuffer{}
				s := NewServer(model.ServerConfiguration{
					Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
					EntityIdentifier:            "https://ta.example.com",
					SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
					EntityConfigurationLifetime: 10 * time.Minute,
					IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
					TrustMarkRetriever:          unreachedTrustMarkRetriever{},
					EntityIdentifierResolver:    failingResolver{err: failure.err, failOn: endpoint.failOn},
					Extensions: model.Extensions{
						SubordinateStatus: model.SubordinateStatusConfiguration{Enabled: true, MetadataRetriever: unreachedSubordinateStatusRetriever{}},
					},
				})
				mux := http.NewServeMux()
				s.Configure(mux)
				ts := httptest.NewServer(mux)
				t.Cleanup(ts.Close)

				response, err := ts.Client().Get(ts.URL + endpoint.path)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer response.Body.Close() //nolint:errcheck
				raw, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("failed to read the response: %v", err)
				}
				var answer map[string]string
				if err := json.Unmarshal(raw, &answer); err != nil {
					t.Fatalf("failed to read the error %s: %v", raw, err)
				}
				description := failure.description
				if description == "" {
					description = endpoint.description
				}
				if response.StatusCode != failure.status || answer["error"] != failure.code || answer["error_description"] != description {
					t.Errorf("[%s] expected %d %s %q, got %d %s", failure.reference, failure.status, failure.code, description, response.StatusCode, raw)
				}

				logged := false
				for _, line := range strings.Split(logs.String(), "\n") {
					if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, failure.err.Error()) {
						logged = true
					}
				}
				if logged != failure.errorLogged {
					t.Errorf("expected the resolver's error logged at error level to be %t, got %s", failure.errorLogged, logs.String())
				}
			})
		}
	}
}
