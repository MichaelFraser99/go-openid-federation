package logging

import (
	"context"
	"log/slog"
)

func LogInfo(l *slog.Logger, ctx context.Context, msg string, args ...any) {
	if l != nil {
		l.InfoContext(ctx, msg, args...)
	}
}

func LogError(l *slog.Logger, ctx context.Context, msg string, args ...any) {
	if l != nil {
		l.ErrorContext(ctx, msg, args...)
	}
}
