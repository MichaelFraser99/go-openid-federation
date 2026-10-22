package trust_chain

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-openid-federation/internal/resolvecache"
	"github.com/MichaelFraser99/go-openid-federation/model"
)

type countingWriter struct {
	bytes atomic.Int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.bytes.Add(int64(len(p)))
	return len(p), nil
}

func TestBuildTrustChain_TheWalkDoesNotLogTheStatementsItCollects(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, sharedDeadEndGraph(12, false), &fetches)

	writer := &countingWriter{}
	cfg := model.Configuration{
		HttpClient: srv.Client(),
		Logger:     slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+"/ta"), resolvecache.New()); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}

	statementBytes := int64(0)
	for range fetches.Load() {
		statementBytes += 1500
	}
	if logged := writer.bytes.Load(); logged > statementBytes {
		t.Errorf("one walk logged %d bytes against roughly %d bytes of statements fetched, so the statements themselves are reaching the log", logged, statementBytes)
	}
}

func TestBuildTrustChain_LogVolumeDoesNotScaleWithTheCallersIdentifierLength(t *testing.T) {
	measure := func(t *testing.T, anchor string) int64 {
		t.Helper()
		var fetches atomic.Int64
		srv := countingHintGraph(t, sharedDeadEndGraph(12, false), &fetches)

		writer := &countingWriter{}
		cfg := model.Configuration{
			HttpClient: srv.Client(),
			Logger:     slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})),
		}

		if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+anchor), resolvecache.New()); err == nil {
			t.Fatal("this graph reaches no trust anchor, so the walk must fail")
		}
		return writer.bytes.Load()
	}

	short := measure(t, "/ta")
	long := measure(t, "/"+strings.Repeat("a", 8192))

	if short == 0 {
		t.Fatal("expected the walk to log something")
	}
	if long > short*2 {
		t.Errorf("an 8192 byte trust anchor took the log from %d bytes to %d: every per-visit record carries the caller's identifier, so its length multiplies the volume", short, long)
	}
}
