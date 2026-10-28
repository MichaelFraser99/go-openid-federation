package model

import (
	"fmt"
	"testing"
	"time"
)

func critEntries(entries int) []any {
	value := make([]any, entries)
	for i := range value {
		value[i] = fmt.Sprintf("https://claims.example.com/%d", i)
	}
	return value
}

func timeCritParse(t *testing.T, value []any) time.Duration {
	t.Helper()
	started := time.Now()
	if _, err := parseCritClaim("crit", value, entityStatementClaims); err != nil {
		t.Fatal(err)
	}
	return time.Since(started)
}

func TestParseCritClaim_CostGrowsLinearlyWithTheEntries(t *testing.T) {
	small, large := critEntries(4_000), critEntries(32_000)
	fastestSmall, fastestLarge := time.Duration(1<<63-1), time.Duration(1<<63-1)
	for range 7 {
		fastestSmall = min(fastestSmall, timeCritParse(t, small))
		fastestLarge = min(fastestLarge, timeCritParse(t, large))
	}
	if ratio := float64(fastestLarge) / float64(max(fastestSmall, time.Microsecond)); ratio > 32 {
		t.Errorf("eight times the entries cost %.0f times as long (%v against %v), so a duplicate check is scanning the entries already parsed", ratio, fastestLarge, fastestSmall)
	}
}
