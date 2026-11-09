package trust_marks

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestValidate_AnIssuerKeyThatCannotBeReadIsLoggedByNameNotByValue(t *testing.T) {
	const (
		anchor    = model.EntityIdentifier("https://ta.example.com")
		subject   = model.EntityIdentifier("https://leaf.example.com")
		markType  = "https://tm.example.com/type"
		peerChose = "PEER-CHOSEN-VALUE"
	)
	secrets := map[string]string{"d": "SECRET-D", "p": "SECRET-P", "q": "SECRET-Q", "dp": "SECRET-DP", "dq": "SECRET-DQ", "qi": "SECRET-QI"}
	unreadable := map[string]any{"kty": "RSA", "kid": "unreadable", "n": "!!!not-base64url!!!", "e": "AQAB", "x-note": peerChose}
	for member, value := range secrets {
		unreadable[member] = value
	}

	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	token, err := jwt.New(signer, map[string]any{"kid": "unreadable", "alg": "ES256", "typ": "trust-mark+jwt"}, map[string]any{
		"iss":             string(anchor),
		"sub":             string(subject),
		"trust_mark_type": markType,
		"iat":             time.Now().UTC().Unix(),
	}, jwt.Opts{Algorithm: jwa.ES256})
	if err != nil {
		t.Fatalf("failed to sign the trust mark: %v", err)
	}

	var logs bytes.Buffer
	cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}
	_, err = Validate(t.Context(), cfg, *token, ValidateOptions{
		ExpectedType:             markType,
		ExpectedSubject:          subject,
		TrustAnchor:              anchor,
		TrustAnchorConfiguration: model.EntityStatement{Iss: anchor, Sub: anchor, JWKs: josemodel.Jwks{Keys: []map[string]any{unreadable}}},
	}, nil)
	if err == nil {
		t.Fatal("a key go-jose cannot read cannot verify the mark, so validation must fail")
	}

	logged := logs.String()
	if !strings.Contains(logged, `"kid":"unreadable"`) || !strings.Contains(logged, string(anchor)) {
		t.Errorf("expected the refusal logged with the key's kid and its issuer, got %s", logged)
	}
	for member, value := range secrets {
		if strings.Contains(logged, value) {
			t.Errorf("the key's private member %q reached the log: %s", member, logged)
		}
		if !strings.Contains(logged, `"`+member+`"`) {
			t.Errorf("expected the key's member names logged, so the operator sees it carried %q, got %s", member, logged)
		}
	}
	if strings.Contains(logged, peerChose) {
		t.Errorf("a value the peer chose inside its key reached the log: %s", logged)
	}
}
