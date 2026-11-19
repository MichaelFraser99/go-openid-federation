package trust_chain

import (
	"fmt"
	"time"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func VerifyChainExpiry(exp int64) error {
	if chainHasExpired(exp) {
		return fmt.Errorf("%w%w", model.ErrExpired, model.NewInvalidTrustChainError("trust chain expired"))
	}
	if exp <= time.Now().UTC().Unix() {
		return fmt.Errorf("%w%w", model.ErrExpired, model.NewInvalidTrustChainError("trust chain expiry is not in the future, so no resolve response can be issued for it"))
	}
	return nil
}

func chainHasExpired(exp int64) bool {
	return time.Now().Add(-model.ClockSkewLeeway).UTC().Unix() >= exp
}

func calculateChainExpiration(chain []model.EntityStatement) int64 {
	exp := chain[0].Exp
	for _, statement := range chain[1:] {
		if statement.Exp < exp {
			exp = statement.Exp
		}
	}
	return exp
}
