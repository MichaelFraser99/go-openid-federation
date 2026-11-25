package server

import (
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNewServer_RefusesAMalformedUnlistedSuperiorsConfiguration(t *testing.T) {
	const wallet, anchor = "https://wallet.example", "https://ta.example"

	tests := []struct {
		name       string
		configured map[model.EntityIdentifier][]model.EntityIdentifier
		fault      string
	}{
		{name: "nothing configured"},
		{name: "an empty map", configured: map[model.EntityIdentifier][]model.EntityIdentifier{}},
		{name: "a superior configured twice", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {anchor, anchor}}},
		{name: "an entity that is not an entity identifier", configured: map[model.EntityIdentifier][]model.EntityIdentifier{"wallet": {anchor}}, fault: `Experimental.UnlistedSuperiors["wallet"] is not an entity identifier`},
		{name: "an entity with no superior", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {}}, fault: `Experimental.UnlistedSuperiors["https://wallet.example"] lists no superior`},
		{name: "a superior that is not an entity identifier", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {"ta"}}, fault: `Experimental.UnlistedSuperiors["https://wallet.example"][0] is not an entity identifier`},
		{name: "a superior that is the entity itself", configured: map[model.EntityIdentifier][]model.EntityIdentifier{wallet: {anchor, "https://Wallet.example/"}}, fault: `Experimental.UnlistedSuperiors["https://wallet.example"][1] names the entity itself`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := jws.GetSigner(jwa.ES256, nil)
			if err != nil {
				t.Fatalf("failed to build a signer: %v", err)
			}
			cfg := model.ServerConfiguration{
				SignerConfiguration: model.SignerConfiguration{Algorithm: "ES256", Signer: signer, KeyID: "ta"},
				EntityIdentifier:    anchor,
			}
			cfg.Experimental.UnlistedSuperiors = tc.configured

			_, err = NewServer(cfg)

			if tc.fault == "" {
				if err != nil {
					t.Fatalf("expected the configuration to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.fault) {
				t.Errorf("expected a refusal naming %q, got %v", tc.fault, err)
			}
		})
	}
}
