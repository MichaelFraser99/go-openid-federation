package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_Resolve_AnOwnSignerFaultIsLoggedAtItsClassesLevelAndOnlyTwice(t *testing.T) {
	tests := []struct {
		name       string
		signerErr  error
		status     int
		errorLines int
	}{
		{name: "a signer that refuses", signerErr: errors.New("the key store refused to sign"), status: http.StatusInternalServerError, errorLines: 2},
		{name: "a throttled signer", signerErr: model.NewTemporarilyUnavailableError("the key store refused to sign"), status: http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			real, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			logs := &lockedBuffer{}
			s := NewServer(model.ServerConfiguration{
				Configuration:               model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))},
				SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: refusingSigner{public: real.Public(), err: tc.signerErr}, KeyID: "ta"},
				EntityConfigurationLifetime: 10 * time.Minute,
				IntermediateConfiguration:   &model.IntermediateConfiguration{SubordinateStatementLifetime: time.Minute},
			})
			mux := http.NewServeMux()
			s.Configure(mux)
			ts := httptest.NewTLSServer(mux)
			t.Cleanup(ts.Close)
			s.SetEntityIdentifier(model.EntityIdentifier(ts.URL))
			s.SetHttpClient(ts.Client())

			response, err := ts.Client().Get(ts.URL + "/resolve?sub=" + ts.URL + "&trust_anchor=" + ts.URL)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			_ = response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, response.StatusCode)
			}

			var errorLines []string
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) {
					errorLines = append(errorLines, line)
				}
			}
			if len(errorLines) != tc.errorLines {
				t.Errorf("expected %d error lines for one signer fault, a 503 at Info and a 500 as the signer's cause plus the walk's context, got %d: %s", tc.errorLines, len(errorLines), strings.Join(errorLines, "\n"))
			}
			if !strings.Contains(logs.String(), "the key store refused to sign") {
				t.Errorf("expected the signer's own text in the log at some level, got %s", logs.String())
			}
		})
	}
}
