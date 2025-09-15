package trust_marks

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/MichaelFraser99/go-openid-federation/internal/logging"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

func Status(ctx context.Context, l *slog.Logger, trustMark string, configuration model.ServerConfiguration) (*model.TrustMarkStatusResponse, error) {
	if configuration.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	status, err := configuration.TrustMarkRetriever.GetTrustMarkStatus(trustMark)
	if err != nil {
		logging.LogInfo(l, ctx, "error determining trust mark status", slog.String("error", err.Error()))
		return nil, err
	}

	return &model.TrustMarkStatusResponse{Active: *status}, nil
}

func List(ctx context.Context, l *slog.Logger, trustMarkIdentifier string, subjectEntityIdentifier *model.EntityIdentifier, configuration model.ServerConfiguration) ([]model.EntityIdentifier, error) {
	if configuration.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	trustMarkedEntities, err := configuration.TrustMarkRetriever.ListTrustMarks(trustMarkIdentifier, subjectEntityIdentifier)
	if err != nil {
		logging.LogInfo(l, ctx, "error listing trust marks", slog.String("error", err.Error()))
		return nil, err
	}

	return trustMarkedEntities, nil
}

func Issue(ctx context.Context, l *slog.Logger, trustMarkIdentifier string, subjectEntityIdentifier model.EntityIdentifier, configuration model.ServerConfiguration) (*string, error) {
	if configuration.TrustMarkRetriever == nil {
		return nil, fmt.Errorf("trust mark retriever not configured")
	}

	trustMark, err := configuration.TrustMarkRetriever.IssueTrustMark(trustMarkIdentifier, subjectEntityIdentifier)
	if err != nil {
		logging.LogInfo(l, ctx, "error issuing trust mark", slog.String("error", err.Error()))
		return nil, err
	}

	return trustMark, nil
}
