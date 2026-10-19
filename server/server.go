package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type Server struct {
	cfg            model.ServerConfiguration
	mu             sync.RWMutex
	authorityHints []model.EntityIdentifier
}

func NewServer(configuration model.ServerConfiguration) *Server {
	configuration.EntityConfiguration.JWKs.Opts.EnforceUniqueKIDs = true
	hints := make([]model.EntityIdentifier, len(configuration.AuthorityHints))
	copy(hints, configuration.AuthorityHints)
	configuration.AuthorityHints = nil
	return &Server{cfg: configuration, authorityHints: hints}
}

// SetEntityIdentifier
//
//	Enables the cfg of the server's Entity Identifier after creation when the identifier
//	is not known to the user beforehand, such as during test server scenarios. Should not be called during
//	production operations
func (s *Server) SetEntityIdentifier(identifier model.EntityIdentifier) {
	s.cfg.EntityIdentifier = identifier
}

// SetHttpClient
//
//	Overrides the server's configured HTTP Client. Intended for test server scenarios.
//	Should not be called during	production operations
func (s *Server) SetHttpClient(client *http.Client) {
	s.cfg.HttpClient = client
}

// AddAuthorityHint
//
//	Adds an authority hint to a running server
func (s *Server) AddAuthorityHint(entityIdentifier model.EntityIdentifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hints := make([]model.EntityIdentifier, len(s.authorityHints), len(s.authorityHints)+1)
	copy(hints, s.authorityHints)
	s.authorityHints = append(hints, entityIdentifier)
}

func (s *Server) AuthorityHints() []model.EntityIdentifier {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hints := make([]model.EntityIdentifier, len(s.authorityHints))
	copy(hints, s.authorityHints)
	return hints
}

func (s *Server) resolveEntityIdentifier(ctx context.Context, param model.EntityIdentifierParam, raw string) (*model.EntityIdentifier, error) {
	resolver := s.cfg.EntityIdentifierResolver
	if resolver == nil {
		resolver = model.StandardEntityIdentifierResolver{}
	}
	return resolver.ResolveEntityIdentifier(ctx, param, raw)
}

func (s *Server) Configure(h *http.ServeMux) {
	if s.cfg.HttpClient == nil {
		s.cfg.HttpClient = http.DefaultClient
	}
	h.HandleFunc("GET /.well-known/openid-federation", s.handle(s.HandleWellKnown))
	if s.cfg.IntermediateConfiguration != nil {
		h.HandleFunc("GET /list", s.handle(s.List))
		h.HandleFunc("GET /fetch", s.handle(s.Fetch))
		h.HandleFunc("GET /resolve", s.handle(s.Resolve))

		if s.cfg.Extensions.ExtendedListing.Enabled {
			h.HandleFunc("GET /extended-list", s.handle(s.ExtendedList))
		}
		if s.cfg.Extensions.SubordinateStatus.Enabled {
			h.HandleFunc("GET /subordinate-status", s.handle(s.SubordinateStatus))
		}
	}
	if s.cfg.TrustMarkRetriever != nil {
		h.HandleFunc("POST /trust-mark-status", s.handle(s.TrustMarkStatus))
		h.HandleFunc("GET /trust-mark-list", s.handle(s.TrustMarkList))
		h.HandleFunc("GET /trust-mark", s.handle(s.TrustMark))
	}
}

var classifiedErrors = []error{
	model.ErrInvalidRequest, model.ErrInvalidClient, model.ErrInvalidIssuer,
	model.ErrInvalidSubject, model.ErrInvalidTrustAnchor, model.ErrInvalidTrustChain,
	model.ErrInvalidMetadata, model.ErrNotFound, model.ErrServerError,
	model.ErrTemporarilyUnavailable, model.ErrUnsupportedParameter,
}

func (s *Server) retrieverError(err error, fallback string) error {
	for _, classified := range classifiedErrors {
		if errors.Is(err, classified) {
			return err
		}
	}
	return model.NewServerError(fallback)
}

const subordinateRetrievalFailureError = "unable to retrieve the subordinate configuration at this time"

const unexpectedFailureError = "an unexpected failure occurred while serving this request"

func (s *Server) handle(handler func(http.ResponseWriter, *http.Request) ResponseFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				func() {
					defer func() { _ = recover() }()
					code, body := s.parseError(model.NewServerError(unexpectedFailureError))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(code)
					_, _ = w.Write([]byte(body))
				}()
				func() {
					defer func() { _ = recover() }()
					s.cfg.LogError(r.Context(), "recovered from a panic while serving a federation endpoint",
						slog.String("path", r.URL.Path),
						slog.String("panic", fmt.Sprintf("%v", recovered)),
						slog.String("stack", string(debug.Stack())))
				}()
			}
		}()
		handler(w, r)()
	}
}

//todo: check all handler functions for duplicated code - prepared to put money on there being a good load of it

func (s *Server) loadSubordinate(ctx context.Context, identifier model.EntityIdentifier) func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
	return func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		subordinate, err := s.cfg.GetSubordinate(ctx, identifier)
		if err != nil {
			s.cfg.LogInfo(ctx, "error retrieving subordinate cfg", slog.String("error", err.Error()))
			if errors.Is(err, model.ErrNotFound) {
				return nil, &s.cfg.SignerConfiguration, nil
			}
			return nil, &s.cfg.SignerConfiguration, s.retrieverError(err, subordinateRetrievalFailureError)
		}
		if subordinate.SignerConfiguration != nil {
			return subordinate, subordinate.SignerConfiguration, nil
		} else {
			return subordinate, &s.cfg.SignerConfiguration, nil
		}
	}
}

type ResponseFunc func()

func (s *Server) respondWith(w http.ResponseWriter, status int, contentType string, data []byte) ResponseFunc {
	return func() {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(data)
	}
}

func (s *Server) RespondWithError(ctx context.Context, w http.ResponseWriter, err error) ResponseFunc {
	s.cfg.LogInfo(ctx, "handling error response", slog.String("error", err.Error()))
	code, response := s.parseError(err)
	return s.respondWith(w, code, "application/json", []byte(response))
}

func (s *Server) RespondWithJSON(w http.ResponseWriter, data []byte) ResponseFunc {
	return s.respondWith(w, http.StatusOK, "application/json", data)
}

func (s *Server) RespondWithTrustMark(w http.ResponseWriter, data []byte) ResponseFunc {
	return s.respondWith(w, http.StatusOK, "application/trust-mark+jwt", data)
}

func (s *Server) RespondWithEntityStatement(w http.ResponseWriter, data []byte) ResponseFunc {
	return s.respondWith(w, http.StatusOK, "application/entity-statement+jwt", data)
}

func (s *Server) RespondWithResolveResponse(w http.ResponseWriter, data []byte) ResponseFunc {
	return s.respondWith(w, http.StatusOK, "application/resolve-response+jwt", data)
}

func (s *Server) RespondWithTrustMarkStatusResponse(w http.ResponseWriter, data []byte) ResponseFunc {
	return s.respondWith(w, http.StatusOK, "application/trust-mark-status-response+jwt", data)
}

func (s *Server) RespondWithSubordinateStatementResponse(w http.ResponseWriter, data []byte) ResponseFunc {
	return s.respondWith(w, http.StatusOK, "application/entity-events-statement+jwt", data)
}

func (s *Server) parseError(err error) (statusCode int, message string) {
	statusCode, errorCode := errorStatusAndCode(err)
	body, marshalErr := json.Marshal(map[string]string{
		"error":             errorCode,
		"error_description": model.TruncateForResponse(err.Error()),
	})
	if marshalErr != nil {
		return http.StatusInternalServerError, fmt.Sprintf(`{"error":"%s"}`, model.ServerError)
	}
	return statusCode, string(body)
}

func errorStatusAndCode(err error) (int, string) {
	switch {
	case errors.Is(err, model.ErrInvalidRequest):
		return http.StatusBadRequest, model.InvalidRequest
	case errors.Is(err, model.ErrInvalidClient):
		return http.StatusUnauthorized, model.InvalidClient
	case errors.Is(err, model.ErrInvalidIssuer):
		return http.StatusNotFound, model.InvalidIssuer
	case errors.Is(err, model.ErrInvalidSubject):
		return http.StatusNotFound, model.InvalidSubject
	case errors.Is(err, model.ErrInvalidTrustAnchor):
		return http.StatusNotFound, model.InvalidTrustAnchor
	case errors.Is(err, model.ErrInvalidTrustChain):
		return http.StatusBadRequest, model.InvalidTrustChain
	case errors.Is(err, model.ErrInvalidMetadata):
		return http.StatusBadRequest, model.InvalidMetadata
	case errors.Is(err, model.ErrNotFound):
		return http.StatusNotFound, model.NotFound
	case errors.Is(err, model.ErrTemporarilyUnavailable):
		return http.StatusServiceUnavailable, model.TemporarilyUnavailable
	case errors.Is(err, model.ErrUnsupportedParameter):
		return http.StatusBadRequest, model.UnsupportedParameter
	default:
		return http.StatusInternalServerError, model.ServerError
	}
}
