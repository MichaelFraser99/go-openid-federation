package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestServer_RespondWithResolveFailure_DoesNotLogAFailureAlreadyLogged(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		errorLine bool
	}{
		"a server error not yet logged":    {err: model.NewServerError("the cause"), errorLine: true},
		"a server error already logged":    {err: fmt.Errorf("%w%w", resolvecache.ErrLogged, model.NewServerError("the cause"))},
		"a loggedFailure from this server": {err: loggedFailure{model.NewServerError("the cause")}},
	} {
		t.Run(name, func(t *testing.T) {
			logs := &lockedBuffer{}
			s := &Server{cfg: model.ServerConfiguration{Configuration: model.Configuration{Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}}}
			recorder := httptest.NewRecorder()
			s.respondWithResolveFailure(t.Context(), recorder, "error filtering trust marks", tc.err)()

			if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), resolveUnavailableError) {
				t.Errorf("[8.9 server_error] expected 500 with the fixed description, got %d %s", recorder.Code, recorder.Body.String())
			}
			if logged := strings.Contains(logs.String(), `"level":"ERROR"`); logged != tc.errorLine {
				t.Errorf("expected an error line to be %t, got %s", tc.errorLine, logs.String())
			}
		})
	}
}
