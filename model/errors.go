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
	ErrLimitReached           = errors.New("")
	ErrNotFound               = errors.New("")
	ErrPageNotFound           = errors.New("")
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
	PageNotFound           = "page_not_found"
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

func NewLimitReachedError(msg string) error {
	return fmt.Errorf("%w%w%s", ErrInvalidTrustAnchor, ErrLimitReached, msg)
}

func NewNotFoundError(msg string) error {
	return fmt.Errorf("%w%s", ErrNotFound, msg)
}

func NewPageNotFoundError(msg string) error {
	return fmt.Errorf("%w%s", ErrPageNotFound, msg)
}

func NewServerError(msg string) error {
	return fmt.Errorf("%w%s", ErrServerError, msg)
}

func NewTemporarilyUnavailableError(msg string) error {
	return fmt.Errorf("%w%s", ErrTemporarilyUnavailable, msg)
}

func ClassifySignerError(err error, description string) error {
	if errors.Is(err, ErrTemporarilyUnavailable) {
		return NewTemporarilyUnavailableError(description)
	}
	return NewServerError(description)
}

func NewUnsupportedParameterError(msg string) error {
	return fmt.Errorf("%w%s", ErrUnsupportedParameter, msg)
}

var classifiedErrorBuilders = []struct {
	sentinel error
	build    func(string) error
}{
	{ErrInvalidRequest, NewInvalidRequestError},
	{ErrInvalidClient, NewInvalidClientError},
	{ErrInvalidIssuer, NewInvalidIssuerError},
	{ErrInvalidSubject, NewInvalidSubjectError},
	{ErrInvalidTrustAnchor, NewInvalidTrustAnchorError},
	{ErrInvalidTrustChain, NewInvalidTrustChainError},
	{ErrInvalidMetadata, NewInvalidMetadataError},
	{ErrNotFound, NewNotFoundError},
	{ErrPageNotFound, NewPageNotFoundError},
	{ErrServerError, NewServerError},
	{ErrTemporarilyUnavailable, NewTemporarilyUnavailableError},
	{ErrUnsupportedParameter, NewUnsupportedParameterError},
}

func ReclassifyWithDescription(err error, description string) error {
	for _, candidate := range classifiedErrorBuilders {
		if errors.Is(err, candidate.sentinel) {
			return candidate.build(description)
		}
	}
	return nil
}

func ClassifiedError(err error) error {
	for _, candidate := range classifiedErrorBuilders {
		if errors.Is(err, candidate.sentinel) {
			return err
		}
	}
	return nil
}
