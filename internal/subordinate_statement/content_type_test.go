package subordinate_statement

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_ContentTypeMatchesMediaType(t *testing.T) {
	tests := map[string]struct {
		contentType string
		rejected    bool
	}{
		"another type with the media type in a parameter": {"text/html; x=application/entity-statement+jwt", true},
		"the media type with a longer subtype":            {"application/entity-statement+jwtx", true},
		"the media type in another case":                  {"Application/Entity-Statement+JWT", false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte("not-a-jwt"))
			}))
			defer s.Close()
			issuer := model.EntityStatement{
				Iss:      model.EntityIdentifier(s.URL),
				Sub:      model.EntityIdentifier(s.URL),
				Metadata: &model.Metadata{FederationMetadata: &model.FederationMetadata{"federation_fetch_endpoint": s.URL + "/fetch"}},
			}
			_, _, err := Retrieve(t.Context(), model.Configuration{HttpClient: s.Client()}, issuer, "https://leaf.example.com")
			if err == nil {
				t.Fatal("expected an error, since the body is not a JWT")
			}
			if got := strings.Contains(err.Error(), "invalid Content-Type"); got != tc.rejected {
				t.Fatalf("[8.1.2] content type %q: expected rejected=%v, got %v", tc.contentType, tc.rejected, err)
			}
		})
	}
}
