package trust_marks

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func issuerWithTwoRoutes(t *testing.T, key *rsa.PrivateKey, constrained map[string]bool) (*httptest.Server, *sync.Map) {
	t.Helper()
	hints := map[string][]string{"issuer": {"a", "b"}, "a": {"ta"}, "b": {"ta"}, "ta": {}}
	asked := &sync.Map{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := func(name string) string { return srv.URL + "/" + name }
		path := strings.TrimPrefix(r.URL.Path, "/")
		now := time.Now().UTC()
		body := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": map[string]any{"keys": []any{federationPublicJwk(t, key.Public(), "test-key")}}}
		if node, ok := strings.CutSuffix(path, "/.well-known/openid-federation"); ok && hints[node] != nil {
			body["iss"], body["sub"] = id(node), id(node)
			body["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": id(node) + "/fetch"}}
			if len(hints[node]) > 0 {
				listed := []any{}
				for _, hint := range hints[node] {
					listed = append(listed, id(hint))
				}
				body["authority_hints"] = listed
			}
		} else if node, ok := strings.CutSuffix(path, "/fetch"); ok && hints[node] != nil {
			subject := strings.TrimPrefix(r.URL.Query().Get("sub"), srv.URL+"/")
			if !slices.Contains(hints[subject], node) {
				http.NotFound(w, r)
				return
			}
			count, _ := asked.LoadOrStore(node+">"+subject, new(int))
			*count.(*int)++
			body["iss"], body["sub"] = id(node), id(subject)
			if constrained[node+">"+subject] {
				body["constraints"] = map[string]any{"max_path_length": 0}
			}
		} else {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(federationSign(t, key, "test-key", body)))
	}))
	t.Cleanup(srv.Close)
	return srv, asked
}

func TestFilterByTrusted_AnIssuerRouteThatFailsValidationGivesWayToAnother(t *testing.T) {
	tests := []struct {
		name        string
		constrained map[string]bool
		kept        int
	}{
		{name: "the anchor's statement about the first route forbids the intermediate below it", constrained: map[string]bool{"ta>a": true}, kept: 1},
		{name: "the anchor's statements about both routes forbid the intermediate below them", constrained: map[string]bool{"ta>a": true, "ta>b": true}},
	}

	key := rvKey(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, asked := issuerWithTwoRoutes(t, key, tc.constrained)
			issuer := srv.URL + "/issuer"
			cfg := model.Configuration{HttpClient: srv.Client()}
			_, anchor, err := entity_configuration.Retrieve(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/ta"), nil)
			if err != nil {
				t.Fatalf("the fixture is wrong: the anchor's configuration does not load, %v", err)
			}
			anchor.TrustMarkIssuers = map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(issuer)}}
			mark := federationTrustMark(t, key, "test-key", issuer, rvType, rvSub)
			resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).Unix(), TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: mark}}}

			if err := FilterByTrusted(t.Context(), cfg, resolved, *anchor, resolvecache.New()); err != nil {
				t.Fatalf("expected the filter to complete, got %v", err)
			}
			if len(resolved.TrustMarks) != tc.kept {
				t.Errorf("[6.2.1, 10.3] the issuer's walk is a trust chain walk like any other, so a valid second route must keep the mark, expected %d marks, got %d", tc.kept, len(resolved.TrustMarks))
			}
			for _, link := range []string{"ta>a", "ta>b"} {
				if count, ok := asked.Load(link); ok && *count.(*int) > 1 {
					t.Errorf("[18.1] expected each route of the issuer walk tried once, %s was asked %d times", link, *count.(*int))
				}
			}
		})
	}
}
