package fasten

import (
	"context"
	"sync"
	"testing"
)

// TestLogSys_DoesNotTagRingRowWithShape pins the store==ring invariant for sys
// rows: LogSys writes the "shape" envelope to stdout on a copy, so the row the
// ring (and any stream store) holds stays clean. A ring-served read must not
// carry a "shape" a store-served read would lack.
func TestLogSys_DoesNotTagRingRowWithShape(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	Default.LogSys(context.Background(), "info", "hello", nil)

	rows, err := GetTransport().QuerySyslog(10, StreamQuery{})
	if err != nil {
		t.Fatalf("QuerySyslog: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if _, ok := rows[0]["shape"]; ok {
		t.Errorf("ring row carries \"shape\" — the stdout envelope leaked into the shared row: %v", rows[0])
	}
}

// TestLogSys_ConcurrentWithReadsNoRace runs LogSys and reader queries
// concurrently. Writing row["shape"] after the ring holds the row would race
// with readers; run under -race to catch it.
func TestLogSys_ConcurrentWithReadsNoRace(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rows, _ := tr.QuerySyslog(50, StreamQuery{})
				for _, r := range rows {
					_ = r["event"] // reads the shared map
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			for j := 0; j < 100; j++ {
				Default.LogSys(context.Background(), "info", "evt", []any{"worker", id})
			}
		}(i)
	}

	writers.Wait()
	close(stop)
	readers.Wait()
}
