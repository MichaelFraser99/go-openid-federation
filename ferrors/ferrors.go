package ferrors

type ErrorCode struct {
	errorType  string
	statusCode int
}

const (
	MissingEntityIdentifier = "unknown entity identifier"
	MissingTrustAnchor      = "unknown trust anchor"
	MissingSubject          = "unknown subject"
)

func InvalidRequestError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_request",
		statusCode: 400,
	}
}

func InvalidClientError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_client",
		statusCode: 401,
	}
}

func InvalidIssuerError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_issuer",
		statusCode: 404,
	}
}

func InvalidSubjectError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_subject",
		statusCode: 404,
	}
}

func InvalidTrustAnchorError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_trust_anchor",
		statusCode: 404,
	}
}

func InvalidTrustChainError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_trust_chain",
		statusCode: 400,
	}
}

func InvalidMetadataError() ErrorCode {
	return ErrorCode{
		errorType:  "invalid_metadata",
		statusCode: 400,
	}
}

func NotFoundError() ErrorCode {
	return ErrorCode{
		errorType:  "not_found",
		statusCode: 404,
	}
}

func ServerError() ErrorCode {
	return ErrorCode{
		errorType:  "server_error",
		statusCode: 500,
	}
}

func TemporarilyUnavailableError() ErrorCode {
	return ErrorCode{
		errorType:  "temporarily_unavailable",
		statusCode: 503,
	}
}

func UnsupportedParameterError() ErrorCode {
	return ErrorCode{
		errorType:  "unsupported_parameter",
		statusCode: 400,
	}
}

type FederationError struct {
	ErrorCode
	errorDescription string
}

func (e FederationError) Type() string {
	return e.errorType
}

func (e FederationError) Description() string {
	return e.errorDescription
}

func (e FederationError) StatusCode() int {
	return e.statusCode
}

func EntityNotFoundError() FederationError {
	return NewError(NotFoundError, MissingEntityIdentifier)
}

func TrustAnchorNotFoundError() FederationError {
	return NewError(NotFoundError, MissingTrustAnchor)
}

func SubjectNotFoundError() FederationError {
	return NewError(NotFoundError, MissingSubject)
}

func NewError(code func() ErrorCode, message string) FederationError {
	return FederationError{
		ErrorCode:        code(),
		errorDescription: message,
	}
}
