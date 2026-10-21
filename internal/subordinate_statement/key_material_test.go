package subordinate_statement

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func registrantRetriever(t *testing.T, registered ...map[string]any) func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
	t.Helper()
	signer, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build signer: %v", err)
	}
	return func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		return &model.SubordinateConfiguration{
			JWKs: josemodel.Jwks{Keys: registered},
		}, &model.SignerConfiguration{Signer: signer, KeyID: "ta", Algorithm: "ES256"}, nil
	}
}

func publishedPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode the published payload: %v", err)
	}
	return string(payload)
}

func TestNew_DropsARegisteredKeyItCannotPublish(t *testing.T) {
	good := map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}

	tests := []struct {
		name       string
		reference  string
		registered []map[string]any
		dropped    []string
		kept       []string
		expectErr  error
	}{
		{
			name:       "a registered public key is published",
			reference:  "RFC 7518 6.2.1",
			registered: []map[string]any{good},
			kept:       []string{"good"},
		},
		{
			name:      "a registered EC key carrying its private exponent is dropped",
			reference: "RFC 7518 6.2.2",
			registered: []map[string]any{
				good,
				{"kid": "leaked-ec", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "SECRETEXPONENT"},
			},
			dropped: []string{"leaked-ec", "SECRETEXPONENT"},
			kept:    []string{"good"},
		},
		{
			name:      "a registered RSA key carrying its primes is dropped",
			reference: "RFC 7518 6.3.2",
			registered: []map[string]any{
				good,
				{"kid": "leaked-rsa", "kty": "RSA", "n": "AQAB", "e": "AQAB", "p": "SECRETPRIME", "q": "AQAB"},
			},
			dropped: []string{"leaked-rsa", "SECRETPRIME"},
			kept:    []string{"good"},
		},
		{
			name:      "a registered symmetric key is dropped",
			reference: "RFC 7518 6.4.1",
			registered: []map[string]any{
				good,
				{"kid": "leaked-oct", "kty": "oct", "k": "SECRETSYMMETRIC"},
			},
			dropped: []string{"leaked-oct", "SECRETSYMMETRIC"},
			kept:    []string{"good"},
		},
		{
			name:      "a registered RSA key below the minimum modulus for the algorithm it is registered for is dropped",
			reference: "RFC 7518 3.3",
			registered: []map[string]any{
				good,
				weakRegisteredKey(t),
			},
			dropped: []string{"weak"},
			kept:    []string{"good"},
		},
		{
			name:      "a subject whose every registered key is unpublishable is refused",
			reference: "8.9",
			registered: []map[string]any{
				{"kid": "leaked-ec", "kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB", "d": "AQAB"},
				{"kid": "leaked-oct", "kty": "oct", "k": "AQAB"},
			},
			expectErr: model.ErrInvalidSubject,
		},
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier: "https://ta.example.com",
		IntermediateConfiguration: &model.IntermediateConfiguration{
			SubordinateStatementLifetime: time.Hour,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			configured := cfg
			configured.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

			token, err := New(t.Context(), "https://leaf.example.com", registrantRetriever(t, tc.registered...), configured)

			if tc.expectErr != nil {
				if err == nil {
					t.Fatalf("[%s] expected the subject to be refused, got a signed statement", tc.reference)
				}
				if !errors.Is(err, tc.expectErr) {
					t.Errorf("[%s] expected %v so the fault is attributed to the subject rather than the server, got %v", tc.reference, tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] one unpublishable registered key must not take down the statement, got %v", tc.reference, err)
			}

			payload := publishedPayload(t, *token)
			for _, absent := range tc.dropped {
				if strings.Contains(payload, absent) {
					t.Errorf("[%s] expected %q to be absent from the published statement", tc.reference, absent)
				}
			}
			for _, present := range tc.kept {
				if !strings.Contains(payload, present) {
					t.Errorf("[%s] expected the usable key %q to still be published", tc.reference, present)
				}
			}
			if len(tc.dropped) > 0 && !strings.Contains(logs.String(), "dropping a registered key") {
				t.Errorf("[%s] an operator must be told a registered key was dropped, got logs %s", tc.reference, logs.String())
			}
		})
	}
}

func weakRegisteredKey(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"kid": "weak",
		"kty": "RSA",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(func() []byte { m := make([]byte, 128); m[0] = 0xFF; return m }()),
		"e":   "AQAB",
	}
}

func TestValidate_APeerRepublishingPrivateMembersIsLoggedAndStillVerified(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		extra     map[string]any
		expectLog string
	}{
		{name: "a superior republishing only the subject's public key", reference: "RFC 7518 6.2.1", extra: nil},
		{name: "a superior republishing the subject's private exponent", reference: "RFC 7518 6.2.2", extra: map[string]any{"d": "AQAB"}, expectLog: "d"},
		{name: "a superior republishing a key the lenient parse drops", reference: "RFC 7517 5", extra: map[string]any{"kty": nil, "k": "AQAB"}, expectLog: "k"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey(t)
			published := testPublicJwk(t, key.Public(), "leaf")
			for member, value := range tc.extra {
				if value == nil {
					delete(published, member)
					continue
				}
				published[member] = value
			}

			issuerKey := testKey(t)
			issuerJwk := testPublicJwk(t, issuerKey.Public(), "ta")
			issuer := model.EntityStatement{
				Iss:  "https://ta.example.com",
				Sub:  "https://ta.example.com",
				JWKs: josemodel.Jwks{Keys: []map[string]any{issuerJwk}},
			}

			statement := testSign(t, issuerKey, map[string]any{"kid": "ta", "typ": "entity-statement+jwt", "alg": "RS256"}, map[string]any{
				"iss":  "https://ta.example.com",
				"sub":  "https://leaf.example.com",
				"iat":  time.Now().UTC().Unix(),
				"exp":  time.Now().Add(time.Hour).UTC().Unix(),
				"jwks": map[string]any{"keys": []any{published}},
			})

			var logs bytes.Buffer
			cfg := model.Configuration{Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

			if _, err := Validate(t.Context(), cfg, issuer, statement); err != nil {
				t.Fatalf("[%s] a superior's mistake must not deny service over the statement, got %v", tc.reference, err)
			}

			logged := strings.Contains(logs.String(), "private key material")
			if logged != (tc.expectLog != "") {
				t.Fatalf("[%s] expected private material logged: %v, got logs %s", tc.reference, tc.expectLog != "", logs.String())
			}
			if tc.expectLog != "" && !strings.Contains(logs.String(), tc.expectLog) {
				t.Errorf("[%s] expected the log to name the member %q, got %s", tc.reference, tc.expectLog, logs.String())
			}
		})
	}
}
