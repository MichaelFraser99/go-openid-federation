package trust_chain

import (
	"log/slog"
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
