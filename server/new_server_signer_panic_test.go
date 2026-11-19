package server

import (
	"crypto"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type panickingPublicSigner struct{}

func (panickingPublicSigner) Public() crypto.PublicKey { panic("hsm.internal is unreachable") }

func (panickingPublicSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not signing")
}

func TestNewServer_ReportsASignerWhosePublicKeyPanics(t *testing.T) {
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("expected NewServer to report the signer, not panic: %v", r)
			}
		}()
		_, err = NewServer(model.ServerConfiguration{
			EntityIdentifier:            "https://entity.example.com",
			SignerConfiguration:         model.SignerConfiguration{Algorithm: "ES256", Signer: panickingPublicSigner{}, KeyID: "own"},
			EntityConfigurationLifetime: time.Hour,
		})
	}()
	if err == nil || !strings.Contains(err.Error(), "SignerConfiguration.Signer cannot give its public key") {
		t.Fatalf("expected the signer named as the fault, got %v", err)
	}
	if strings.Contains(err.Error(), "hsm.internal") {
		t.Errorf("expected the panic's value not to reach the error, got %v", err)
	}
}

func TestServer_AddAuthorityHint_KeepsTheCauseOfARefusal(t *testing.T) {
	s := mustNewServer(t, model.ServerConfiguration{EntityIdentifier: "https://entity.example.com", EntityConfigurationLifetime: time.Hour})
	err := s.AddAuthorityHint("http://insecure.example.com")
	if err == nil {
		t.Fatal("expected an http hint to be refused")
	}
	if errors.Unwrap(err) == nil {
		t.Errorf("expected the refusal to wrap the identifier's cause, got %v", err)
	}
}
