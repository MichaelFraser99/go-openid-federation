package model

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"unicode/utf8"
)

const MaxLoggedValueBytes = 1024

func TruncateAtCharacter(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for step := 0; step < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(value[cut]); step++ {
		cut--
	}
	if !utf8.RuneStart(value[cut]) {
		cut = limit
	}
	return value[:cut] + "..."
}

func truncateLoggedValue(value string) string {
	return TruncateAtCharacter(value, MaxLoggedValueBytes)
}

func boundLogArgs(args []any) []any {
	bounded := make([]any, len(args))
	for i, arg := range args {
		if attr, ok := arg.(slog.Attr); ok {
			bounded[i] = slog.Attr{Key: truncateLoggedValue(attr.Key), Value: boundLogValue(attr.Value)}
			continue
		}
		bounded[i] = boundLogValue(slog.AnyValue(arg)).Any()
	}
	return bounded
}

func boundLogValue(value slog.Value) slog.Value {
	value = value.Resolve()
	switch value.Kind() {
	case slog.KindString:
		return slog.StringValue(truncateLoggedValue(value.String()))
	case slog.KindGroup:
		members := value.Group()
		bounded := make([]slog.Attr, len(members))
		for i, member := range members {
			bounded[i] = slog.Attr{Key: truncateLoggedValue(member.Key), Value: boundLogValue(member.Value)}
		}
		return slog.GroupValue(bounded...)
	case slog.KindAny:
		if err, isError := value.Any().(error); isError {
			return slog.StringValue(truncateLoggedValue(err.Error()))
		}
		encoded, err := json.Marshal(value.Any())
		if err != nil {
			return slog.StringValue(fmt.Sprintf("a %T that cannot be logged", value.Any()))
		}
		if len(encoded) > MaxLoggedValueBytes {
			return slog.StringValue(truncateLoggedValue(string(encoded)))
		}
		return value
	default:
		return value
	}
}
