package server

import (
	"context"
	"encoding/json"
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

type listsEveryHolder struct{ unreachedTrustMarkRetriever }

func (listsEveryHolder) ListTrustMarks(_ context.Context, _ string, subject *model.EntityIdentifier) ([]model.EntityIdentifier, error) {
	if subject != nil {
		return []model.EntityIdentifier{*subject}, nil
	}
	return []model.EntityIdentifier{"https://one.example.com", "https://two.example.com"}, nil
}

func TestServer_AResolverThatReturnsNoIdentifierAndNoErrorAnswersTheEndpointsFixedDescription(t *testing.T) {
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

	for _, endpoint := range endpoints {
		t.Run(strings.SplitN(endpoint.path, "?", 2)[0]+" refusing "+string(endpoint.failOn), func(t *testing.T) {
			logs := &lockedBuffer{}
			s := NewServer(model.ServerConfiguration{
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				EntityIdentifier:            "https://ta.example.com",
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
				TrustMarkRetriever:          listsEveryHolder{},
				EntityIdentifierResolver:    failingResolver{failOn: endpoint.failOn},
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
			if err := json.Unmarshal(raw, &answer); err != nil || response.StatusCode != http.StatusInternalServerError || answer["error"] != model.ServerError || answer["error_description"] != endpoint.description {
				t.Errorf("[8.9 server_error] a resolver that returns neither an identifier nor an error is broken configuration, so expected 500 server_error %q, got %d %s", endpoint.description, response.StatusCode, raw)
			}
			if strings.Contains(logs.String(), "recovered from a panic") {
				t.Errorf("expected the missing identifier refused before any handler used it, but a handler panicked: %s", logs.String())
			}
			logged := false
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) && strings.Contains(line, "returned no identifier and no error") && strings.Contains(line, string(endpoint.failOn)) {
					logged = true
				}
			}
			if !logged {
				t.Errorf("expected the broken resolver logged at error level naming the parameter, got %s", logs.String())
			}
		})
	}
}
