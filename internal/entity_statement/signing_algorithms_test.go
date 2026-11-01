package entity_statement

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func signedAs(t *testing.T, signer crypto.Signer, alg jwa.Algorithm) string {
	t.Helper()
	token, err := jwt.New(signer, map[string]any{"kid": "k", "typ": "entity-statement+jwt", "alg": alg.String()}, map[string]any{"iss": "https://leaf.example.com"}, jwt.Opts{Algorithm: alg})
	if err != nil {
		t.Fatalf("failed to sign with %s: %v", alg, err)
	}
	return *token
}

func ed25519Key(t *testing.T) (ed25519.PrivateKey, map[string]any) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	published, err := jwk.PublicJwk(public)
	if err != nil {
		t.Fatalf("failed to build jwk: %v", err)
	}
	(*published)["kid"] = "k"
	return private, *published
}

func TestVerifyAgainstJwks_AcceptsOnlyTheAlgorithmsItIsGiven(t *testing.T) {
	edPrivate, edPublic := ed25519Key(t)
	ed := signedAs(t, edPrivate, jwa.Ed25519)
	eddsa := signedEdDSA(edPrivate)

	tests := map[string]struct {
		token      string
		key        map[string]any
		algorithms []jwa.Algorithm
		expectErr  string
	}{
		"Ed25519 under the default":                  {token: ed, key: edPublic, algorithms: model.DefaultSigningAlgorithms},
		"Ed25519 under a list that names it":         {token: ed, key: edPublic, algorithms: []jwa.Algorithm{jwa.Ed25519}},
		"Ed25519 under a list that does not name it": {token: ed, key: edPublic, algorithms: []jwa.Algorithm{jwa.ES256}, expectErr: "names an algorithm this deployment does not accept"},
		"EdDSA under the default":                    {token: eddsa, key: edPublic, algorithms: model.DefaultSigningAlgorithms},
		"EdDSA under a list that does not name it":   {token: eddsa, key: edPublic, algorithms: []jwa.Algorithm{jwa.Ed25519}, expectErr: "names an algorithm this deployment does not accept"},
		"an empty list accepts nothing":              {token: ed, key: edPublic, algorithms: []jwa.Algorithm{}, expectErr: "does not accept"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifyAgainstJwks(t.Context(), tc.token, "k", josemodel.Jwks{Keys: []map[string]any{tc.key}}, tc.algorithms)
			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[RFC 8725 3.1] expected the signature to verify, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[RFC 8725 3.1] expected a refusal naming %q, got %v", tc.expectErr, err)
			}
			if VerifyAgainstAnyKey(t.Context(), tc.token, josemodel.Jwks{Keys: []map[string]any{tc.key}}, tc.algorithms) == nil {
				t.Errorf("[RFC 8725 3.1] a token refused when its key is selected by kid must also be refused against the whole set")
			}
		})
	}
}

func TestVerifyAgainstJwks_RefusesHSItselfRatherThanLeavingItToGoJose(t *testing.T) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate the secret: %v", err)
	}
	signer, err := jws.GetSigner(jwa.HS256, &josemodel.Opts{SecretKey: &secret})
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	token, err := jwt.New(signer, map[string]any{"kid": "oct", "typ": "entity-statement+jwt", "alg": "HS256"}, map[string]any{"iss": "https://leaf.example.com"}, jwt.Opts{Algorithm: jwa.HS256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	oct := map[string]any{"kid": "oct", "kty": "oct", "k": base64.RawURLEncoding.EncodeToString(secret)}

	err = VerifyAgainstJwks(t.Context(), *token, "oct", josemodel.Jwks{Keys: []map[string]any{oct}}, model.DefaultSigningAlgorithms)
	if err == nil || !strings.Contains(err.Error(), "names an algorithm this deployment does not accept") {
		t.Fatalf("[3.2] HS256 must be refused by this library's own list, got %v", err)
	}
}

func TestKeyCanVerify_FollowsTheAlgorithmsItIsGiven(t *testing.T) {
	_, edPublic := ed25519Key(t)
	tests := map[string]struct {
		key        map[string]any
		algorithms []jwa.Algorithm
		usable     bool
	}{
		"an Ed25519 key under the default":                         {key: edPublic, algorithms: model.DefaultSigningAlgorithms, usable: true},
		"an Ed25519 key under a list without Ed25519 or EdDSA":     {key: edPublic, algorithms: []jwa.Algorithm{jwa.ES256, jwa.RS256}},
		"an Ed25519 key under a list naming only EdDSA":            {key: edPublic, algorithms: []jwa.Algorithm{jwa.EdDSA}, usable: true},
		"an Ed25519 key declaring Ed25519 under a list without it": {key: withMember(edPublic, "alg", "Ed25519"), algorithms: []jwa.Algorithm{jwa.EdDSA}},
		"an Ed25519 key under an empty list":                       {key: edPublic, algorithms: []jwa.Algorithm{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := KeyCanVerify(tc.key, tc.algorithms); got != tc.usable {
				t.Errorf("[RFC 8725 3.1] expected usable=%v, got %v", tc.usable, got)
			}
		})
	}
}

func signedEdDSA(private ed25519.PrivateKey) string {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k","typ":"entity-statement+jwt"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://leaf.example.com"}`))
	signature := ed25519.Sign(private, []byte(head+"."+body))
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func withMember(key map[string]any, member string, value any) map[string]any {
	copied := make(map[string]any, len(key)+1)
	for k, v := range key {
		copied[k] = v
	}
	copied[member] = value
	return copied
}
