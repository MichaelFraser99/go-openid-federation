package model

import (
	"fmt"
	"testing"
	"time"
)

func fastestCritParse(t *testing.T, entries int) time.Duration {
	t.Helper()
	value := make([]any, entries)
	for i := range value {
		value[i] = fmt.Sprintf("https://claims.example.com/%d", i)
	}
	fastest := time.Duration(1<<63 - 1)
	for range 5 {
		started := time.Now()
		if _, err := parseCritClaim("crit", value, entityStatementClaims); err != nil {
			t.Fatal(err)
		}
		fastest = min(fastest, time.Since(started))
	}
	return fastest
}

func TestParseCritClaim_CostGrowsLinearlyWithTheEntries(t *testing.T) {
	small := fastestCritParse(t, 1_000)
	large := fastestCritParse(t, 8_000)
	if ratio := float64(large) / float64(max(small, time.Microsecond)); ratio > 24 {
		t.Errorf("eight times the entries cost %.0f times as long (%v against %v), so a duplicate check is scanning the entries already parsed", ratio, large, small)
	}
}
