package subordinate_statement

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_RequestsTheFetchEndpointAsPublished(t *testing.T) {
	tests := map[string]struct {
		endpoint string
		subject  model.EntityIdentifier
		expect   string
	}{
		"a plain path":                    {endpoint: "/fetch", subject: "https://leaf.example.com", expect: "/fetch?sub=https%3A%2F%2Fleaf.example.com"},
		"a path with a trailing slash":    {endpoint: "/federation/fetch/", subject: "https://leaf.example.com", expect: "/federation/fetch/?sub=https%3A%2F%2Fleaf.example.com"},
		"a query value ending in a slash": {endpoint: "/fetch?tenant=a/", subject: "https://leaf.example.com", expect: "/fetch?tenant=a/&sub=https%3A%2F%2Fleaf.example.com"},
		"an existing query":               {endpoint: "/fetch?tenant=a&region=eu", subject: "https://leaf.example.com", expect: "/fetch?tenant=a&region=eu&sub=https%3A%2F%2Fleaf.example.com"},
		"an empty query":                  {endpoint: "/fetch?", subject: "https://leaf.example.com", expect: "/fetch?sub=https%3A%2F%2Fleaf.example.com"},
		"a percent-encoded path segment":  {endpoint: "/fed%2Ffetch/", subject: "https://leaf.example.com", expect: "/fed%2Ffetch/?sub=https%3A%2F%2Fleaf.example.com"},
		"a subject that needs escaping":   {endpoint: "/fetch", subject: "https://leaf.example.com/a b?c=d&e", expect: "/fetch?sub=https%3A%2F%2Fleaf.example.com%2Fa+b%3Fc%3Dd%26e"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var requested string
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested = r.RequestURI
				w.WriteHeader(http.StatusNotFound)
			}))
			defer s.Close()

			issuer := model.EntityStatement{
				Iss:      model.EntityIdentifier(s.URL),
				Sub:      model.EntityIdentifier(s.URL),
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": s.URL + tc.endpoint}},
			}
			_, _, _ = Retrieve(t.Context(), model.Configuration{HttpClient: s.Client()}, issuer, tc.subject)
			if requested == "" {
				t.Fatal("no request reached the fetch endpoint")
			}
			if requested != tc.expect {
				t.Errorf("[5.1.1, 8.1.1] expected the request %q, got %q", tc.expect, requested)
			}
		})
	}
}
