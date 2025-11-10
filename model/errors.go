package model

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidRequest         = errors.New("")
	ErrInvalidClient          = errors.New("")
	ErrInvalidIssuer          = errors.New("")
	ErrInvalidSubject         = errors.New("")
	ErrInvalidTrustAnchor     = errors.New("")
	ErrInvalidTrustChain      = errors.New("")
	ErrInvalidMetadata        = errors.New("")
	ErrNotFound               = errors.New("")
	ErrServerError            = errors.New("")
	ErrTemporarilyUnavailable = errors.New("")
	ErrUnsupportedParameter   = errors.New("")
)

const (
	InvalidRequest         = "invalid_request"
	InvalidClient          = "invalid_client"
	InvalidIssuer          = "invalid_issuer"
	InvalidSubject         = "invalid_subject"
	InvalidTrustAnchor     = "invalid_trust_anchor"
	InvalidTrustChain      = "invalid_trust_chain"
	InvalidMetadata        = "invalid_metadata"
	NotFound               = "not_found"
	ServerError            = "server_error"
	TemporarilyUnavailable = "temporarily_unavailable"
	UnsupportedParameter   = "unsupported_parameter"
)

func NewInvalidRequestError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidRequest, msg)
}

func NewInvalidClientError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidClient, msg)
}

func NewInvalidIssuerError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidIssuer, msg)
}

func NewInvalidSubjectError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidSubject, msg)
}

func NewInvalidTrustAnchorError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidTrustAnchor, msg)
}

func NewInvalidTrustChainError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidTrustChain, msg)
}

func NewInvalidMetadataError(msg string) error {
	return fmt.Errorf("%w%s", ErrInvalidMetadata, msg)
}

func NewNotFoundError(msg string) error {
	return fmt.Errorf("%w%s", ErrNotFound, msg)
}

func NewServerError(msg string) error {
	return fmt.Errorf("%w%s", ErrServerError, msg)
}

func NewTemporarilyUnavailableError(msg string) error {
	return fmt.Errorf("%w%s", ErrTemporarilyUnavailable, msg)
}

func NewUnsupportedParameterError(msg string) error {
	return fmt.Errorf("%w%s", ErrUnsupportedParameter, msg)
}
