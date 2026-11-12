package trust_marks

import (
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestFilterByTrusted_AMarksTypAndAlgAreJudgedBeforeTheIssuerWalk(t *testing.T) {
	tests := []struct {
		name       string
		head       map[string]any
		algorithms []jwa.Algorithm
		walked     bool
	}{
		{name: "a well-formed header, so the walk runs and the signature is judged", head: map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}, walked: true},
		{name: "typ JWT", head: map[string]any{"kid": "test-key", "typ": "JWT", "alg": "RS256"}},
		{name: "no typ", head: map[string]any{"kid": "test-key", "alg": "RS256"}},
		{name: "a typ that is not a string", head: map[string]any{"kid": "test-key", "typ": 7, "alg": "RS256"}},
		{name: "alg none", head: map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "none"}},
		{name: "alg HS256", head: map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "HS256"}},
		{name: "no alg", head: map[string]any{"kid": "test-key", "typ": "trust-mark+jwt"}},
		{name: "an alg this deployment does not accept", head: map[string]any{"kid": "test-key", "typ": "trust-mark+jwt", "alg": "RS256"}, algorithms: []jwa.Algorithm{jwa.ES256}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRvFed(t, map[string]string{"member": "ta"})
			ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("member"))}})
			body := map[string]any{"iss": f.id("member"), "sub": rvSub, "trust_mark_type": rvType, "iat": time.Now().UTC().Unix(), "exp": time.Now().Add(time.Hour).UTC().Unix()}
			mark := rawRSAToken(t, f.ecKey["ta"], tc.head, body)

			cfg := model.Configuration{HttpClient: f.server.Client(), SigningAlgorithms: tc.algorithms}
			resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(time.Hour).UTC().Unix(), TrustMarks: []model.TrustMarkHolder{{TrustMarkType: rvType, TrustMark: mark}}}
			if err := FilterByTrusted(t.Context(), cfg, resolved, ta, nil); err != nil {
				t.Fatalf("[8.3] a mark that fails is dropped, never refused, got %v", err)
			}
			if len(resolved.TrustMarks) != 0 {
				t.Fatalf("[7.3] expected the mark dropped, got %v", resolved.TrustMarks)
			}

			f.mu.Lock()
			fetched := f.hits["/member/.well-known/openid-federation"]
			f.mu.Unlock()
			if walked := fetched > 0; walked != tc.walked {
				t.Errorf("[18.1] expected the issuer walked: %t, got %d fetches of the issuer's entity configuration", tc.walked, fetched)
			}
		})
	}
}
