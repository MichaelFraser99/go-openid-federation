package entity_configuration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jws"
	josemodel "github.com/MichaelFraser99/go-jose/model"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func TestNew_RefusesAHeaderItsOwnReadPathRejects(t *testing.T) {
	signerConfiguration, _ := issuanceSigner(t)

	rsaSigner, err := jws.GetSigner(josemodel.RS256, nil)
	if err != nil {
		t.Fatalf("failed to build an RSA signer: %v", err)
	}

	tests := []struct {
		name      string
		step      string
		algorithm string
		signer    any
		expectErr string
	}{
		{name: "an alg of none", step: "3.2 step 3", algorithm: "none", expectErr: "refusing to publish"},
		{name: "an empty alg", step: "3.2 step 3", algorithm: "", expectErr: "refusing to publish"},
		{name: "an alg in the wrong case", step: "3.2 step 3", algorithm: "es256", expectErr: "refusing to publish"},
		{name: "an unknown alg", step: "3.2 step 3", algorithm: "banana", expectErr: "refusing to publish"},
		{name: "an alg that does not match the key", step: "3.2 step 12", algorithm: "RS256", signer: rsaSigner, expectErr: "refusing to publish"},
		{name: "a conforming alg is published", step: "3.2 step 3", algorithm: "ES256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer := signerConfiguration.Signer
			cfg := model.ServerConfiguration{
				EntityIdentifier: "https://leaf.example.com",
				SignerConfiguration: model.SignerConfiguration{
					Signer:    signer,
					KeyID:     signerConfiguration.KeyID,
					Algorithm: tc.algorithm,
				},
				EntityConfigurationLifetime: time.Hour,
			}

			token, err := New(t.Context(), cfg)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the configuration to be issued, got %v", tc.step, err)
				}
				if _, rerr := Validate(context.Background(), model.Configuration{}, "https://leaf.example.com", *token); rerr != nil {
					t.Fatalf("[%s] the issued configuration is rejected by this library's own read path: %v", tc.step, rerr)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected issuance to be refused, got a signed configuration this library would reject", tc.step)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected an error containing %q, got %v", tc.step, tc.expectErr, err)
			}
		})
	}
}

func TestNew_RefusesAnAlgorithmThatDoesNotMatchTheKey(t *testing.T) {
	ecSigner, err := jws.GetSigner(josemodel.ES256, nil)
	if err != nil {
		t.Fatalf("failed to build an EC signer: %v", err)
	}

	cfg := model.ServerConfiguration{
		EntityIdentifier: "https://leaf.example.com",
		SignerConfiguration: model.SignerConfiguration{
			Signer:    ecSigner,
			KeyID:     "leaf",
			Algorithm: "RS256",
		},
		EntityConfigurationLifetime: time.Hour,
	}

	if _, err := New(t.Context(), cfg); err == nil {
		t.Fatal("[3.2 step 12] expected RS256 over an EC key to be refused at issuance")
	} else if !strings.Contains(err.Error(), "refusing to publish") {
		t.Fatalf("[3.2 step 12] expected a refusal to publish, got %v", err)
	}
}
