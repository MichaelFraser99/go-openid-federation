package trust_marks

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/internal/entity_configuration"
	"github.com/MichaelFraser99/go-openid-federation/internal/trust_chain"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type rvFed struct {
	server   *httptest.Server
	ecKey    map[string]*rsa.PrivateKey
	ssKey    map[string]*rsa.PrivateKey
	superior map[string]string
	ssSigner map[string]*rsa.PrivateKey
	mu       sync.Mutex
	hits     map[string]int
}

func rvKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (f *rvFed) id(name string) string { return f.server.URL + "/" + name }

func newRvFed(t *testing.T, superior map[string]string) *rvFed {
	t.Helper()
	f := &rvFed{ecKey: map[string]*rsa.PrivateKey{}, ssKey: map[string]*rsa.PrivateKey{}, superior: superior, ssSigner: map[string]*rsa.PrivateKey{}, hits: map[string]int{}}
	names := map[string]struct{}{"ta": {}}
	for s, sup := range superior {
		names[s] = struct{}{}
		names[sup] = struct{}{}
	}
	for n := range names {
		f.ecKey[n] = rvKey(t)
	}
	isSuperior := func(n string) bool {
		for _, sup := range superior {
			if sup == n {
				return true
			}
		}
		return false
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasSuffix(path, "/.well-known/openid-federation") {
			n := strings.TrimSuffix(path, "/.well-known/openid-federation")
			key, ok := f.ecKey[n]
			if !ok {
				http.NotFound(w, r)
				return
			}
			body := map[string]any{
				"iss": f.id(n), "sub": f.id(n),
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
				"jwks":     map[string]any{"keys": []any{federationPublicJwk(t, key.Public(), "test-key")}},
				"metadata": map[string]any{},
			}
			if isSuperior(n) {
				body["metadata"] = map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": f.id(n) + "/fetch"}}
			}
			if sup, ok := superior[n]; ok {
				body["authority_hints"] = []string{f.id(sup)}
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write([]byte(federationSign(t, key, "test-key", body)))
			return
		}
		if strings.HasSuffix(path, "/fetch") {
			sup := strings.TrimSuffix(path, "/fetch")
			sub := r.URL.Query().Get("sub")
			name := strings.TrimPrefix(sub, f.server.URL+"/")
			if superior[name] != sup {
				http.NotFound(w, r)
				return
			}
			pub := f.ecKey[name]
			if k, ok := f.ssKey[name]; ok {
				pub = k
			}
			signer := f.ecKey[sup]
			if k, ok := f.ssSigner[sup]; ok {
				signer = k
			}
			body := map[string]any{
				"iss": f.id(sup), "sub": sub,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
				"jwks": map[string]any{"keys": []any{federationPublicJwk(t, pub.Public(), "test-key")}},
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write([]byte(federationSign(t, signer, "test-key", body)))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *rvFed) taConfig(t *testing.T, tmIssuers map[string][]model.EntityIdentifier) model.EntityStatement {
	t.Helper()
	_, ec, err := entity_configuration.Retrieve(t.Context(), model.Configuration{HttpClient: f.server.Client()}, model.EntityIdentifier(f.id("ta")), nil)
	if err != nil {
		t.Fatalf("retrieve ta: %v", err)
	}
	ec.TrustMarkIssuers = tmIssuers
	return *ec
}

func (f *rvFed) filter(t *testing.T, ta model.EntityStatement, marks ...model.TrustMarkHolder) []model.TrustMarkHolder {
	t.Helper()
	resolved := &model.ResolveResponse{Sub: "https://subject.example.com", Exp: time.Now().Add(24 * time.Hour).Unix(), TrustMarks: marks}
	if err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client()}, resolved, ta, nil); err != nil {
		t.Fatal(err)
	}
	return resolved.TrustMarks
}

const rvType = "https://tm.example.com/a"
const rvSub = "https://subject.example.com"

func TestFilterByTrusted_TrustAnchorAsIssuerIsKept(t *testing.T) {
	f := newRvFed(t, map[string]string{})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("ta"))}})
	tm := federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), rvType, rvSub)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 1 {
		t.Fatalf("trust anchor issued mark dropped")
	}
}

func TestFilterByTrusted_IssuerUnderIntermediateIsKept(t *testing.T) {
	f := newRvFed(t, map[string]string{"int": "ta", "issuer": "int"})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("issuer"))}})
	tm := federationTrustMark(t, f.ecKey["issuer"], "test-key", f.id("issuer"), rvType, rvSub)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 1 {
		t.Fatalf("issuer under an intermediate dropped")
	}
}

func TestFilterByTrusted_TrustAnchorReKeyDropsOldIssuerKey(t *testing.T) {
	f := newRvFed(t, map[string]string{"issuer": "ta"})
	f.ssKey["issuer"] = rvKey(t)
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("issuer"))}})
	tm := federationTrustMark(t, f.ecKey["issuer"], "test-key", f.id("issuer"), rvType, rvSub)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
		t.Fatalf("mark signed with key the TA no longer registers was kept")
	}
}

func TestFilterByTrusted_IntermediateWellKnownTakeoverForgesIssuerKey(t *testing.T) {
	f := newRvFed(t, map[string]string{"int": "ta", "issuer": "int"})
	genuineInt := f.ecKey["int"]
	attacker := rvKey(t)
	f.ssKey["int"] = genuineInt
	f.ecKey["int"] = attacker
	f.ssKey["issuer"] = attacker
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("issuer"))}})
	tm := federationTrustMark(t, attacker, "test-key", f.id("issuer"), rvType, rvSub)
	got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm})

	chain, _, _, err := trust_chain.BuildTrustChain(t.Context(), model.Configuration{HttpClient: f.server.Client()}, model.EntityIdentifier(f.id("issuer")), model.EntityIdentifier(f.id("ta")), nil)
	if err != nil {
		t.Logf("build: %v", err)
	} else {
		_, resolveErr := trust_chain.ResolveMetadata(t.Context(), model.Configuration{HttpClient: f.server.Client()}, "https://resolver.example.com", chain, nil)
		t.Logf("ResolveMetadata on the same issuer chain: err=%v", resolveErr)
	}
	if len(got) != 0 {
		t.Fatalf("mark signed by attacker who only controls the intermediate's well-known was kept")
	}
}

func TestFilterByTrusted_OwnedTypeWithEmptyIssuerListNeedsNoDelegation(t *testing.T) {
	f := newRvFed(t, map[string]string{"member": "ta"})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {}})
	ta.TrustMarkOwners = map[string]any{rvType: map[string]any{"sub": "https://owner.example.com", "jwks": map[string]any{"keys": []any{}}}}
	tm := federationTrustMark(t, f.ecKey["member"], "test-key", f.id("member"), rvType, rvSub)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
		t.Fatalf("owned type with empty issuer list accepted from any federation member without delegation")
	}
}

func TestFilterByTrusted_Issue79ListedIssuerWithoutChainDropped(t *testing.T) {
	f := newRvFed(t, map[string]string{})
	f.ecKey["loner"] = rvKey(t)
	for _, types := range []map[string][]model.EntityIdentifier{{rvType: {model.EntityIdentifier(f.id("loner"))}}, {rvType: {}}} {
		ta := f.taConfig(t, types)
		tm := federationTrustMark(t, f.ecKey["loner"], "test-key", f.id("loner"), rvType, rvSub)
		if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
			t.Fatalf("issuer with no chain kept for %v", types)
		}
	}
}

func TestValidate_RequiresAnExpectedTypeAndSubject(t *testing.T) {
	f := newRvFed(t, map[string]string{"issuer": "ta"})
	ta := f.taConfig(t, nil)
	tm := federationTrustMark(t, f.ecKey["issuer"], "test-key", f.id("issuer"), "https://other-type", "https://someone-else.example.com")

	tests := []struct {
		name string
		opts ValidateOptions
	}{
		{
			name: "no expected type or subject",
			opts: ValidateOptions{TrustAnchor: ta.Sub, TrustAnchorConfiguration: ta},
		},
		{
			name: "no expected subject",
			opts: ValidateOptions{ExpectedType: "https://other-type", TrustAnchor: ta.Sub, TrustAnchorConfiguration: ta},
		},
		{
			name: "no expected type",
			opts: ValidateOptions{ExpectedSubject: "https://someone-else.example.com", TrustAnchor: ta.Sub, TrustAnchorConfiguration: ta},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Validate(t.Context(), model.Configuration{HttpClient: f.server.Client()}, tm, tc.opts, nil)
			if err == nil {
				t.Fatalf("expected validation to refuse incomplete options, got trust mark %v", result)
			}
		})
	}
}

func TestFilterByTrusted_IntermediateAndIssuerHostTakeoverForgesMark(t *testing.T) {
	f := newRvFed(t, map[string]string{"int": "ta", "issuer": "int"})
	genuineInt := f.ecKey["int"]
	intAttacker := rvKey(t)
	issuerAttacker := rvKey(t)
	f.ssKey["int"] = genuineInt
	f.ecKey["int"] = intAttacker
	f.ecKey["issuer"] = issuerAttacker
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {model.EntityIdentifier(f.id("issuer"))}})
	tm := federationTrustMark(t, issuerAttacker, "test-key", f.id("issuer"), rvType, rvSub)
	if got := f.filter(t, ta, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: tm}); len(got) != 0 {
		t.Fatalf("FORGERY: mark signed by an attacker holding no genuine key was kept")
	}
}

func TestFilterByTrusted_IssuerLimitErrorLeavesNoUnverifiedMarks(t *testing.T) {
	f := newRvFed(t, map[string]string{})
	ta := f.taConfig(t, map[string][]model.EntityIdentifier{rvType: {}})

	marks := []model.TrustMarkHolder{{
		TrustMarkType: rvType,
		TrustMark:     federationTrustMark(t, f.ecKey["ta"], "test-key", f.id("ta"), rvType, rvSub),
	}}
	for i := range 2 {
		parts := strings.Split(federationTrustMark(t, f.ecKey["ta"], "test-key", fmt.Sprintf("https://junk-%d.invalid", i), rvType, rvSub), ".")
		marks = append(marks, model.TrustMarkHolder{TrustMarkType: rvType, TrustMark: parts[0] + "." + parts[1] + ".AAAA"})
	}

	resolved := &model.ResolveResponse{Sub: rvSub, Exp: time.Now().Add(24 * time.Hour).Unix(), TrustMarks: marks}

	err := FilterByTrusted(t.Context(), model.Configuration{HttpClient: f.server.Client(), MaxTrustMarkIssuers: 2}, resolved, ta, nil)
	if err == nil {
		t.Fatalf("expected the issuer limit to be reported")
	}
	if len(resolved.TrustMarks) != 0 {
		t.Errorf("expected no unverified trust marks left on the response after the limit error, got %d", len(resolved.TrustMarks))
	}
}
