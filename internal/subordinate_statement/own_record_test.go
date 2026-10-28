package subordinate_statement

import (
	"crypto"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func freshSigner(t *testing.T) crypto.Signer {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func publicKeyOf(t *testing.T, signer crypto.Signer, kid string) map[string]any {
	t.Helper()
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	(*public)["kid"] = kid
	return *public
}

func withLeadingZeroOctet(t *testing.T, key map[string]any, member string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(key[member].(string))
	if err != nil {
		t.Fatal(err)
	}
	padded := map[string]any{}
	for k, v := range key {
		padded[k] = v
	}
	padded[member] = base64.RawURLEncoding.EncodeToString(append([]byte{0}, raw...))
	return padded
}

func TestNew_RefusesARecordThatIsTheServersOwn(t *testing.T) {
	serverSigner := freshSigner(t)
	publishedOnly := freshSigner(t)
	rotatedAway := freshSigner(t)
	registrant := freshSigner(t)

	tests := map[string]struct {
		registered func(t *testing.T) []map[string]any
		expectErr  bool
	}{
		"a genuine subordinate holding its own key": {
			registered: func(t *testing.T) []map[string]any { return []map[string]any{publicKeyOf(t, registrant, "leaf")} },
		},
		"a record holding the server's signing key": {
			registered: func(t *testing.T) []map[string]any { return []map[string]any{publicKeyOf(t, serverSigner, "anything")} },
			expectErr:  true,
		},
		"a record holding a key the server publishes but does not sign with": {
			registered: func(t *testing.T) []map[string]any {
				return []map[string]any{publicKeyOf(t, publishedOnly, "published")}
			},
			expectErr: true,
		},
		"the server's key beside the registrant's own": {
			registered: func(t *testing.T) []map[string]any {
				return []map[string]any{publicKeyOf(t, registrant, "leaf"), publicKeyOf(t, serverSigner, "ta")}
			},
			expectErr: true,
		},
		"the server's key with leading zero octets": {
			registered: func(t *testing.T) []map[string]any {
				return []map[string]any{withLeadingZeroOctet(t, publicKeyOf(t, serverSigner, "ta"), "x")}
			},
			expectErr: true,
		},
		"a registrant key sharing only the server's kid": {
			registered: func(t *testing.T) []map[string]any { return []map[string]any{publicKeyOf(t, registrant, "ta")} },
		},
		"a key the server has rotated away from is not known to it": {
			registered: func(t *testing.T) []map[string]any { return []map[string]any{publicKeyOf(t, rotatedAway, "old")} },
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := model.ServerConfiguration{
				EntityIdentifier:    "https://ta.example.com/ta",
				SignerConfiguration: model.SignerConfiguration{Signer: serverSigner, KeyID: "ta", Algorithm: "ES256"},
				EntityConfiguration: model.EntityStatement{JWKs: josemodel.Jwks{Keys: []map[string]any{publicKeyOf(t, publishedOnly, "published")}}},
				IntermediateConfiguration: &model.IntermediateConfiguration{
					SubordinateStatementLifetime: time.Hour,
				},
			}
			retriever := func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
				return &model.SubordinateConfiguration{JWKs: josemodel.Jwks{Keys: tc.registered(t)}}, &cfg.SignerConfiguration, nil
			}

			token, err := New(t.Context(), "https://ta.example.com/TA", retriever, cfg)
			if !tc.expectErr {
				if err != nil || token == nil {
					t.Fatalf("expected a statement for a record that is not the server's own, got %v", err)
				}
				return
			}
			if !errors.Is(err, model.ErrInvalidSubject) {
				t.Fatalf("[8.1.2] expected a record holding the server's own key to be refused as invalid_subject, got %v", err)
			}
		})
	}
}
