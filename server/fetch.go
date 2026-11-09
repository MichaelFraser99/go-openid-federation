package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/MichaelFraser99/go-openid-federation/internal/subordinate_statement"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

const subordinateStatementUnavailableError = "unable to produce the subordinate statement at this time"

func (s *Server) Fetch(w http.ResponseWriter, r *http.Request) ResponseFunc {
	ctx := r.Context()
	sub := r.URL.Query().Get("sub")

	if sub == "" {
		s.cfg.LogInfo(ctx, "no sub query parameter found")
		return s.RespondWithError(ctx, w, model.NewInvalidRequestError("request missing required parameter 'sub'"))
	}

	token, err := s.issueSubordinateStatement(ctx, sub)
	if err != nil {
		return s.RespondWithError(ctx, w, err)
	}

	return s.RespondWithEntityStatement(w, []byte(*token))
}

func (s *Server) issueSubordinateStatement(ctx context.Context, sub string) (*string, error) {
	parsedSub, err := s.resolveEntityIdentifier(ctx, model.EntityIdentifierParamSub, sub, subordinateStatementUnavailableError)
	if err != nil {
		return nil, err
	}

	if model.NamesTheSameEntity(*parsedSub, s.cfg.EntityIdentifier) {
		s.cfg.LogInfo(ctx, "provided 'sub' parameter matches server entity identifier")
		return nil, model.NewInvalidRequestError("an entity cannot issue a subordinate statement for itself")
	}

	token, err := subordinate_statement.New(ctx, *parsedSub, s.loadSubordinate(ctx, *parsedSub, s.newPublishedKeys()), s.cfg)
	if err != nil {
		classified := s.retrieverError(err, subordinateStatementUnavailableError)
		s.logFailure(ctx, "error creating subordinate statement", classified, slog.String("error", err.Error()))
		return nil, classified
	}
	return token, nil
}

func (s *Server) ownSubordinateStatement(ctx context.Context, issuer model.EntityStatement, subject model.EntityIdentifier) (*string, *model.EntityStatement, error) {
	signed, err := s.issueSubordinateStatement(ctx, string(subject))
	if err != nil {
		if errors.Is(err, model.ErrTemporarilyUnavailable) {
			return nil, nil, model.NewTemporarilyUnavailableError(subordinateStatementUnavailableError)
		}
		if errors.Is(err, model.ErrServerError) || model.ClassifiedError(err) == nil {
			return nil, nil, model.NewServerError(subordinateStatementUnavailableError)
		}
		return nil, nil, model.NewInvalidTrustChainError("this server does not issue a subordinate statement for the subject")
	}
	accepted, statement, err := subordinate_statement.Accept(ctx, s.cfg.Configuration, issuer, subject, *signed)
	if err != nil {
		s.cfg.LogError(ctx, "this server's own subordinate statement does not pass the checks a resolver applies to it", slog.String("subject", string(subject)), slog.String("error", err.Error()))
		return nil, nil, model.NewServerError(subordinateStatementUnavailableError)
	}
	return accepted, statement, nil
}
