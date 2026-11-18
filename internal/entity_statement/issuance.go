package entity_statement

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-openid-federation/internal/truncate"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func VerifyIssuanceAlgorithm(name string) error {
	algorithm := jwa.GetAlgorithm(name)
	switch {
	case algorithm == jwa.HS256 || algorithm == jwa.HS384 || algorithm == jwa.HS512:
		return fmt.Errorf("%s is never used to sign here: a federation key is published, so a symmetric key would not be secret", name)
	case algorithm == jwa.EdDSA:
		return fmt.Errorf("EdDSA is accepted only for verification, because RFC 9864 section 4.1.2 deprecates it; sign with Ed25519")
	case algorithm == jwa.Unknown || !slices.Contains(model.DefaultSigningAlgorithms(), algorithm):
		return fmt.Errorf("%q is not a supported signing algorithm", truncate.TruncateForResponse(name))
	}
	return nil
}

func ResolveStatementLifetime(name string, configured, fallback time.Duration) (time.Duration, error) {
	if configured < 0 {
		return 0, fmt.Errorf("%s must not be negative, got %s", name, configured)
	}
	if configured == 0 {
		return fallback, nil
	}
	if configured < time.Second {
		return 0, fmt.Errorf("%s must be at least one second, got %s", name, configured)
	}
	return configured, nil
}

func VerifyIssuedStatement(claims []byte, registry model.EntityTypeRegistry) error {
	var issued model.EntityStatement
	if err := json.Unmarshal(claims, &issued); err != nil {
		return err
	}
	if issued.Metadata != nil {
		if err := issued.Metadata.Verify(registry, false); err != nil {
			return err
		}
	}
	if issued.MetadataPolicy != nil {
		if err := issued.MetadataPolicy.Verify(registry, false); err != nil {
			return err
		}
	}
	return nil
}
