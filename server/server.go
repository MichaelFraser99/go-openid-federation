package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
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
	s.route(h, "/.well-known/openid-federation", s.HandleWellKnown, http.MethodGet)
	if s.cfg.IntermediateConfiguration != nil {
		s.route(h, "/list", s.List, http.MethodGet)
		s.route(h, "/fetch", s.Fetch, http.MethodGet)
		s.route(h, "/resolve", s.Resolve, http.MethodGet)

		if s.cfg.Extensions.ExtendedListing.Enabled {
			s.route(h, "/extended-list", s.ExtendedList, http.MethodGet)
		}
		if s.cfg.Extensions.SubordinateStatus.Enabled {
			s.route(h, "/subordinate-status", s.SubordinateStatus, http.MethodGet)
		}
	}
	if s.cfg.TrustMarkRetriever != nil {
		s.route(h, "/trust-mark-status", s.TrustMarkStatus, http.MethodPost)
		s.route(h, "/trust-mark-list", s.TrustMarkList, http.MethodGet)
		s.route(h, "/trust-mark", s.TrustMark, http.MethodGet)
	}
}

var everyMethod = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
}

func (s *Server) route(h *http.ServeMux, path string, handler func(http.ResponseWriter, *http.Request) ResponseFunc, methods ...string) {
	allowed := make([]string, 0, len(methods)+1)
	for _, method := range methods {
		h.HandleFunc(method+" "+path, s.handle(handler))
		allowed = append(allowed, method)
		if method == http.MethodGet {
			allowed = append(allowed, http.MethodHead)
		}
	}

	refuse := s.handle(s.methodNotAllowed(strings.Join(allowed, ", ")))
	for _, method := range everyMethod {
		if !slices.Contains(allowed, method) {
			h.HandleFunc(method+" "+path, refuse)
		}
	}
}

func (s *Server) methodNotAllowed(allowed string) func(http.ResponseWriter, *http.Request) ResponseFunc {
	return func(w http.ResponseWriter, r *http.Request) ResponseFunc {
		return func() {
			s.cfg.LogInfo(r.Context(), "rejecting a request made with an unsupported method",
				slog.String("path", r.URL.Path), slog.String("method", model.TruncateForResponse(r.Method)), slog.String("allowed", allowed))
			_, body := s.parseError(model.NewInvalidRequestError(fmt.Sprintf("this endpoint accepts %s", allowed)))
			w.Header().Set("Allow", allowed)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(body))
		}
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
	case errors.Is(err, model.ErrPageNotFound):
		return http.StatusNotFound, model.PageNotFound
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
