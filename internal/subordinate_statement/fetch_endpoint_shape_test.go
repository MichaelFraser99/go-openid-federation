package subordinate_statement

import (
	"errors"
	"net/http"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestRetrieve_RefusesAFetchEndpointThatIsNotAString(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		endpoint  any
	}{
		{name: "a number", reference: "5.1.1", endpoint: 7},
		{name: "an object", reference: "5.1.1", endpoint: map[string]any{}},
		{name: "an array", reference: "5.1.1", endpoint: []any{"https://ta.example.com/fetch"}},
		{name: "a boolean", reference: "5.1.1", endpoint: true},
		{name: "an empty string", reference: "5.1.1", endpoint: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] a federation fetch endpoint of an unexpected type panicked the fetch: %v", tc.reference, r)
				}
			}()

			metadata := model.FederationMetadata{"federation_fetch_endpoint": tc.endpoint}
			issuer := model.EntityStatement{
				Iss:      "https://ta.example.com",
				Sub:      "https://ta.example.com",
				Metadata: &model.Metadata{FederationMetadata: &metadata},
			}

			_, _, err := Retrieve(t.Context(), model.Configuration{HttpClient: http.DefaultClient}, issuer, "https://leaf.example.com")
			if err == nil {
				t.Fatalf("[%s] expected the fetch to be refused", tc.reference)
			}
			if !errors.Is(err, model.ErrInvalidTrustChain) {
				t.Errorf("[%s] a superior publishing an unusable fetch endpoint is the superior's fault, got %v", tc.reference, err)
			}
		})
	}
}
