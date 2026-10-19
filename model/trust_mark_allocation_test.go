package model

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestTrustMarkHolder_BoundsAllocationForALargeTrustMark(t *testing.T) {
	const inputBytes = 1 << 20
	const allocationCeiling = 2 * inputBytes

	holder := []byte(`{"trust_mark_type":"https://tm.example.com/a","trust_mark":"` + strings.Repeat(".", inputBytes) + `"}`)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var parsed TrustMarkHolder
	if err := json.Unmarshal(holder, &parsed); err == nil {
		t.Fatal("expected a trust mark of bare separators to be refused")
	}

	runtime.ReadMemStats(&after)

	used := after.TotalAlloc - before.TotalAlloc
	if used > allocationCeiling {
		t.Fatalf("parsing a %d byte trust mark allocated %d bytes, which exceeds the %d byte ceiling", inputBytes, used, allocationCeiling)
	}
}
