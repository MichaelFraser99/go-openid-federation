package server

import (
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func mustNewServer(t testing.TB, configuration model.ServerConfiguration) *Server {
	t.Helper()
	if configuration.SignerConfiguration == (model.SignerConfiguration{}) {
		signer, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatalf("failed to build a test signer: %v", err)
		}
		configuration.SignerConfiguration = model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "test-server"}
	}
	server, err := NewServer(configuration)
	if err != nil {
		t.Fatalf("expected the configuration to be valid, got %v", err)
	}
	return server
}
