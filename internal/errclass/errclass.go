package errclass

import (
	"errors"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

func ClassifySignerError(err error, description string) error {
	if errors.Is(err, model.ErrTemporarilyUnavailable) {
		return model.NewTemporarilyUnavailableError(description)
	}
	return model.NewServerError(description)
}
