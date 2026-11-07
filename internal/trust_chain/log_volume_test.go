package trust_chain

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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

type lineCountingWriter struct {
	mu    sync.Mutex
	lines []string
}

func (w *lineCountingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, string(p))
	return len(p), nil
}

type walkSummary struct {
	Steps         int  `json:"steps"`
	Described     int  `json:"entities_described"`
	KnownNoRoute  int  `json:"skipped_known_no_route"`
	KnownDeadEnd  int  `json:"skipped_dead_end"`
	DepthRefusals int  `json:"depth_refusals"`
	Found         bool `json:"found"`
}

func (w *lineCountingWriter) summaries(t *testing.T) []walkSummary {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var found []walkSummary
	for _, line := range w.lines {
		if !strings.Contains(line, `"msg":"trust chain walk finished"`) {
			continue
		}
		var summary walkSummary
		if err := json.Unmarshal([]byte(line), &summary); err != nil {
			t.Fatalf("failed to read the summary line: %v", err)
		}
		found = append(found, summary)
	}
	return found
}

func denseRingGraph(nodes, fanOut int) map[string][]string {
	hints := map[string][]string{"ta": nil, "subject": {"n0"}}
	for i := range nodes {
		targets := make([]string, 0, fanOut)
		for j := 1; j <= fanOut; j++ {
			targets = append(targets, fmt.Sprintf("n%d", (i+j)%nodes))
		}
		hints[fmt.Sprintf("n%d", i)] = targets
	}
	return hints
}

func TestBuildTrustChain_TheLinesOneWalkLogsAreBoundedByTheEntitiesItFetches(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, denseRingGraph(1000, 64), &fetches)

	writer := &lineCountingWriter{}
	cfg := model.Configuration{
		HttpClient: srv.Client(),
		Logger:     slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	cache := resolvecache.New()

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), model.EntityIdentifier(srv.URL+"/ta"), cache); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}

	fetched := int(fetches.Load())
	if fetched < 100 {
		t.Fatalf("expected the dense graph to make the walk fetch many entities, got %d", fetched)
	}
	if lines := len(writer.lines); lines > 4*fetched+16 {
		t.Errorf("[18.1] one walk over %d fetched entities logged %d lines: the peer chose the graph, so the volume must follow what the walk fetches, not how often it steps back into an entity", fetched, lines)
	}
	summaries := writer.summaries(t)
	if len(summaries) != 1 {
		t.Fatalf("expected one summary line for the walk, carrying what the per-step lines no longer say, got %d", len(summaries))
	}
	summary := summaries[0]
	if summary.Found {
		t.Error("expected the summary to record that no route was found")
	}
	if summary.Steps != cache.Traversed() {
		t.Errorf("expected the summary's steps to be the %d entities the walk stepped into, got %d", cache.Traversed(), summary.Steps)
	}
	if summary.Described != fetched {
		t.Errorf("expected every one of the %d fetched entities described once, got %d", fetched, summary.Described)
	}
	if summary.KnownNoRoute == 0 || summary.DepthRefusals == 0 {
		t.Errorf("expected the dense ring to make the walk skip known entities and refuse at depth, got %+v", summary)
	}
}

func TestBuildTrustChain_TheSummaryCountsTheDeadEndsAnEarlierWalkFound(t *testing.T) {
	var fetches atomic.Int64
	srv := countingHintGraph(t, sharedDeadEndGraph(12, false), &fetches)

	writer := &lineCountingWriter{}
	cfg := model.Configuration{
		HttpClient: srv.Client(),
		Logger:     slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	cache := resolvecache.New()
	anchor := model.EntityIdentifier(srv.URL + "/ta")
	for _, subject := range []string{"/subject", "/issuer", "/subject"} {
		if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+subject), anchor, cache); err == nil {
			t.Fatal("this graph reaches no trust anchor, so the walk must fail")
		}
	}

	summaries := writer.summaries(t)
	if len(summaries) != 3 {
		t.Fatalf("expected one summary line per walk, got %d", len(summaries))
	}
	got := []int{summaries[0].KnownDeadEnd, summaries[1].KnownDeadEnd, summaries[2].KnownDeadEnd}
	if got[0] != 0 || got[1] != 12 || got[2] != 1 {
		t.Errorf("expected the second walk to skip the 12 dead ends the first found as hints, and the third to skip its own subject, got %v", got)
	}
}

func TestBuildTrustChain_AnEntityIsDescribedOnceForTheRequestAcrossItsWalks(t *testing.T) {
	var fetches atomic.Int64
	graph := denseRingGraph(200, 16)
	graph["issuer"] = []string{"n100"}
	srv := countingHintGraph(t, graph, &fetches)

	writer := &lineCountingWriter{}
	cfg := model.Configuration{
		HttpClient: srv.Client(),
		Logger:     slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	cache := resolvecache.New()
	anchor := model.EntityIdentifier(srv.URL + "/ta")

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/subject"), anchor, cache); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}
	firstWalk := len(writer.lines)
	steppedBefore := cache.Traversed()
	fetchedBefore := int(fetches.Load())

	if _, _, _, err := BuildTrustChain(t.Context(), cfg, model.EntityIdentifier(srv.URL+"/issuer"), anchor, cache); err == nil {
		t.Fatal("this graph reaches no trust anchor, so the walk must fail")
	}

	if stepped := cache.Traversed() - steppedBefore; stepped < 100 {
		t.Fatalf("expected the second walk to step back through the cached ring, got %d steps", stepped)
	}
	fetched := int(fetches.Load()) - fetchedBefore
	if added := len(writer.lines) - firstWalk; added > 4*fetched+8 {
		t.Errorf("[18.1] a second walk in the same request, as a trust mark issuer walk is, fetched %d new entities and logged %d more lines, so it described again the entities the first walk had", fetched, added)
	}
}
