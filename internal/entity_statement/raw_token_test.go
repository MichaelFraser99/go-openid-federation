package entity_statement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func rawRSAToken(t *testing.T, key *rsa.PrivateKey, head, body map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := encode(head) + "." + encode(body)
	alg, _ := head["alg"].(string)
	hash := crypto.SHA256
	switch alg {
	case "RS384", "PS384":
		hash = crypto.SHA384
	case "RS512", "PS512":
		hash = crypto.SHA512
	}
	hasher := hash.New()
	hasher.Write([]byte(input))
	digest := hasher.Sum(nil)
	var signature []byte
	var err error
	if strings.HasPrefix(alg, "PS") {
		signature, err = rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else {
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
