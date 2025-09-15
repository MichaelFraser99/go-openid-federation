package server

import (
	"context"
	"fmt"
	"github.com/MichaelFraser99/go-openid-federation/ferrors"
	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/model"
	"log/slog"
	"net/http"
)

type Server struct {
	configuration model.ServerConfiguration
	l             *slog.Logger
}

func NewServer(configuration model.ServerConfiguration) *Server {
	configuration.EntityConfiguration.JWKs.Opts.EnforceUniqueKIDs = true
	return &Server{configuration: configuration}
}

func (s *Server) WithLogger(l *slog.Logger) {
	s.l = l
}

// SetEntityIdentifier
//
//	Enables the configuration of the server's Entity Identifier after creation when the identifier
//	is not known to the user beforehand, such as during test server scenarios. Should not be called during
//	production operations
func (s *Server) SetEntityIdentifier(identifier model.EntityIdentifier) {
	s.configuration.EntityIdentifier = identifier
}

// SetHttpClient
//
//	Overrides the server's configured HTTP Client. Intended for test server scenarios.
//	Should not be called during	production operations
func (s *Server) SetHttpClient(client *http.Client) {
	s.configuration.HttpClient = client
}

// AddAuthorityHint
//
//	Adds an authority hint to a running server
func (s *Server) AddAuthorityHint(entityIdentifier model.EntityIdentifier) {
	s.configuration.AuthorityHints = append(s.configuration.AuthorityHints, entityIdentifier)
}

func (s *Server) Configure(h *http.ServeMux) {
	if s.configuration.HttpClient == nil {
		s.configuration.HttpClient = http.DefaultClient
	}
	h.HandleFunc("GET /.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) { s.HandleWellKnown(w, r)() })
	if s.configuration.IntermediateConfiguration != nil {
		h.HandleFunc("GET /list", func(w http.ResponseWriter, r *http.Request) { s.List(w, r)() })
		h.HandleFunc("GET /fetch", func(w http.ResponseWriter, r *http.Request) { s.Fetch(w, r)() })
		h.HandleFunc("GET /resolve", func(w http.ResponseWriter, r *http.Request) { s.Resolve(w, r)() })

		if s.configuration.Extensions.ExtendedListing.Enabled {
			h.HandleFunc("GET /extended-list", func(w http.ResponseWriter, r *http.Request) { s.ExtendedList(w, r)() })
		}
	}
	if s.configuration.TrustMarkRetriever != nil {
		h.HandleFunc("GET /trust-mark-status", func(w http.ResponseWriter, r *http.Request) { s.TrustMarkStatus(w, r)() })
		h.HandleFunc("GET /trust-mark-list", func(w http.ResponseWriter, r *http.Request) { s.TrustMarkList(w, r)() })
		h.HandleFunc("GET /trust-mark", func(w http.ResponseWriter, r *http.Request) { s.TrustMark(w, r)() })
	}
}

//todo: check all handler functions for duplicated code - prepared to put money on there being a good load of it

func (s *Server) getSignerForIdentifier(identifier model.EntityIdentifier) func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
	return func() (*model.SubordinateConfiguration, *model.SignerConfiguration, error) {
		subordinate, err := s.configuration.GetSubordinate(identifier)
		if err != nil {
			logging.LogInfo(s.l, context.Background(), "error retrieving subordinate configuration", slog.String("error", err.Error()))
			return nil, &s.configuration.SignerConfiguration, nil
		}
		if subordinate.SignerConfiguration != nil {
			return subordinate, subordinate.SignerConfiguration, nil
		} else {
			return subordinate, &s.configuration.SignerConfiguration, nil
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

func (s *Server) RespondWithError(ctx context.Context, w http.ResponseWriter, err ferrors.FederationError) ResponseFunc {
	logging.LogInfo(s.l, ctx, "handling error response", slog.String("error", err.Type()), slog.String("error_description", err.Description()))
	return s.respondWith(w, err.StatusCode(), "application/json", []byte(fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, err.Type(), err.Description())))
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
