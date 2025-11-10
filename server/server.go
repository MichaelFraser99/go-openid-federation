package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/model"
)

type Server struct {
	cfg model.ServerConfiguration
	l   *slog.Logger
}

func NewServer(configuration model.ServerConfiguration) *Server {
	configuration.EntityConfiguration.JWKs.Opts.EnforceUniqueKIDs = true
	return &Server{cfg: configuration}
}

func (s *Server) WithLogger(l *slog.Logger) {
	s.l = l
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
	s.cfg.AuthorityHints = append(s.cfg.AuthorityHints, entityIdentifier)
}

func (s *Server) Configure(h *http.ServeMux) {
	if s.cfg.HttpClient == nil {
		s.cfg.HttpClient = http.DefaultClient
	}
	h.HandleFunc("GET /.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) { s.HandleWellKnown(w, r)() })
	if s.cfg.IntermediateConfiguration != nil {
		h.HandleFunc("GET /list", func(w http.ResponseWriter, r *http.Request) { s.List(w, r)() })
		h.HandleFunc("GET /fetch", func(w http.ResponseWriter, r *http.Request) { s.Fetch(w, r)() })
		h.HandleFunc("GET /resolve", func(w http.ResponseWriter, r *http.Request) { s.Resolve(w, r)() })

		if s.cfg.Extensions.ExtendedListing.Enabled {
			h.HandleFunc("GET /extended-list", func(w http.ResponseWriter, r *http.Request) { s.ExtendedList(w, r)() })
		}
		if s.cfg.Extensions.SubordinateStatus.Enabled {
			h.HandleFunc("GET /subordinate-status", func(w http.ResponseWriter, r *http.Request) { s.SubordinateStatus(w, r)() })
		}
	}
	if s.cfg.TrustMarkRetriever != nil {
		h.HandleFunc("GET /trust-mark-status", func(w http.ResponseWriter, r *http.Request) { s.TrustMarkStatus(w, r)() })
		h.HandleFunc("GET /trust-mark-list", func(w http.ResponseWriter, r *http.Request) { s.TrustMarkList(w, r)() })
		h.HandleFunc("GET /trust-mark", func(w http.ResponseWriter, r *http.Request) { s.TrustMark(w, r)() })
	}
}

//todo: check all handler functions for duplicated code - prepared to put money on there being a good load of it

func (s *Server) loadSubordinate(ctx context.Context, identifier model.EntityIdentifier) func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
	return func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		subordinate, err := s.cfg.GetSubordinate(ctx, identifier)
		if err != nil {
			s.cfg.LogInfo(ctx, "error retrieving subordinate cfg", slog.String("error", err.Error()))
			return nil, &s.cfg.SignerConfiguration, nil
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
	switch {
	case errors.Is(err, model.ErrInvalidRequest):
		return http.StatusBadRequest, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidRequest, err.Error())
	case errors.Is(err, model.ErrInvalidClient):
		return http.StatusUnauthorized, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidClient, err.Error())
	case errors.Is(err, model.ErrInvalidIssuer):
		return http.StatusNotFound, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidIssuer, err.Error())
	case errors.Is(err, model.ErrInvalidSubject):
		return http.StatusNotFound, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidSubject, err.Error())
	case errors.Is(err, model.ErrInvalidTrustAnchor):
		return http.StatusNotFound, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidTrustAnchor, err.Error())
	case errors.Is(err, model.ErrInvalidTrustChain):
		return http.StatusBadRequest, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidTrustChain, err.Error())
	case errors.Is(err, model.ErrInvalidMetadata):
		return http.StatusBadRequest, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.InvalidMetadata, err.Error())
	case errors.Is(err, model.ErrNotFound):
		return http.StatusNotFound, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.NotFound, err.Error())
	case errors.Is(err, model.ErrTemporarilyUnavailable):
		return http.StatusServiceUnavailable, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.TemporarilyUnavailable, err.Error())
	case errors.Is(err, model.ErrUnsupportedParameter):
		return http.StatusBadRequest, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.UnsupportedParameter, err.Error())
	default:
		return http.StatusInternalServerError, fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, model.ServerError, err.Error())
	}
}
