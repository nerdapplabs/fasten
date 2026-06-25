package fasten

import (
	"strings"
	"testing"
)

// Sentinel request_id invariant — every stream row always carries a
// request_id, so /correlate is a contract. Context-less rows get the shared
// boot id during startup, a unique orphan id afterwards.

func TestSentinel_MintAndClassify(t *testing.T) {
	rid := MintSentinel("orphan", "svc")
	if !strings.HasPrefix(rid, "orphan-svc-") {
		t.Errorf("mint: got %q", rid)
	}
	if !IsSentinel(rid) || RequestIDKind(rid) != "orphan" {
		t.Errorf("classify sentinel: kind=%q sentinel=%v", RequestIDKind(rid), IsSentinel(rid))
	}
	if RequestIDKind("3a7b1c9d") != "request" {
		t.Errorf("real id misclassified as %q", RequestIDKind("3a7b1c9d"))
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("MintSentinel(bogus) should panic")
			}
		}()
		MintSentinel("bogus", "svc")
	}()
}

func TestSentinel_ContextlessPushGetsBootThenOrphan(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushAPI(APIRow{"method": "GET", "path": "/a"})                         // boot
	tr.PushAPI(APIRow{"method": "GET", "path": "/b", "request_id": "real-1"}) // ends boot
	tr.PushAPI(APIRow{"method": "GET", "path": "/c"})                         // orphan

	got := map[string]string{}
	rows, err := tr.QueryAPI(100, "", "", "")
	if err != nil {
		t.Fatalf("QueryAPI: %v", err)
	}
	for _, r := range rows {
		got[r["path"].(string)] = r["request_id"].(string)
	}
	if RequestIDKind(got["/a"]) != "boot" {
		t.Errorf("/a: want boot, got %q (%s)", got["/a"], RequestIDKind(got["/a"]))
	}
	if got["/b"] != "real-1" {
		t.Errorf("/b: explicit id changed to %q", got["/b"])
	}
	if RequestIDKind(got["/c"]) != "orphan" {
		t.Errorf("/c: want orphan, got %q (%s)", got["/c"], RequestIDKind(got["/c"]))
	}
}

func TestSentinel_ExplicitRequestIDUntouched(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"level": "warn", "event": "x", "request_id": "my-own-id"})
	rows, _ := tr.QuerySyslog(100, "", "", "")
	if rows[0]["request_id"] != "my-own-id" {
		t.Errorf("explicit id changed to %v", rows[0]["request_id"])
	}
}

// Conformance: the contract under which /correlate and completeness are
// designed — no stream row ever lacks a request_id, across a mixed workload.
func TestSentinel_NoStreamRowLacksRequestID(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"level": "info", "event": "boot.init"}) // boot
	tr.PushAPI(APIRow{"method": "GET", "path": "/health"})          // boot
	tr.PushAPI(APIRow{"method": "POST", "path": "/x", "request_id": "op-1"})
	tr.PushSyslog(SyslogRow{"level": "error", "event": "boom", "request_id": "op-1"})
	tr.PushSyslog(SyslogRow{"level": "info", "event": "bg.tick"}) // orphan

	sys, _ := tr.QuerySyslog(1000, "", "", "")
	api, _ := tr.QueryAPI(1000, "", "", "")
	n := 0
	for _, r := range sys {
		if rid, _ := r["request_id"].(string); rid == "" {
			t.Errorf("syslog row lacks request_id: %v", r)
		}
		n++
	}
	for _, r := range api {
		if rid, _ := r["request_id"].(string); rid == "" {
			t.Errorf("api row lacks request_id: %v", r)
		}
		n++
	}
	if n == 0 {
		t.Fatalf("expected rows")
	}
}

func TestSentinel_BootRowsAreCorrelatable(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"level": "error", "event": "db.connect.failed"}) // boot
	rows, _ := tr.QuerySyslog(100, "", "", "")
	bootID := rows[0]["request_id"].(string)
	if RequestIDKind(bootID) != "boot" {
		t.Fatalf("expected boot id, got %q", bootID)
	}

	body, code := getJSON(t, NewReader(), "/correlate?request_id="+bootID)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	counts, _ := body["counts"].(map[string]any)
	if counts["sys"] != float64(1) {
		t.Errorf("boot correlate: got %v sys rows, want 1", counts["sys"])
	}
}
