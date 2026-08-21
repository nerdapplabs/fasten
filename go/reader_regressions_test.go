package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func status(t *testing.T, h http.Handler, url string) int {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
	return rr.Code
}

// M2 — a non-positive / non-integer / over-max limit is refused with 422 on the
// structured-query endpoints, not silently coerced to the default.
func TestLimitRejectedWith422(t *testing.T) {
	registerTestCodes(t)
	db, _ := sql.Open("sqlite", ":memory:")
	store, err := NewSQLiteStore(db, "audit_lim422")
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	h := NewReader()
	for _, ep := range []string{"/audit", "/sys", "/api"} {
		for _, bad := range []string{"0", "-5", "abc", "5000"} {
			if code := status(t, h, ep+"?limit="+bad); code != 422 {
				t.Errorf("%s?limit=%s -> %d, want 422", ep, bad, code)
			}
		}
		if code := status(t, h, ep+"?limit=50"); code != 200 {
			t.Errorf("%s?limit=50 -> %d, want 200", ep, code)
		}
		if code := status(t, h, ep); code != 200 {
			t.Errorf("%s (no limit) -> %d, want 200", ep, code)
		}
	}
	if code := status(t, h, "/correlate?request_id=x&limit=0"); code != 422 {
		t.Errorf("/correlate limit=0 -> %d, want 422", code)
	}
}

// PR #59 finding 8 — offset / after / since / until / search-limit are
// parsed strictly on the Go audit + topology + search endpoints. A corrupted
// cursor (?after=12a3) used to silently fall back to 0 and re-serve page one
// (client paging to exhaustion loops forever); a bad ?since= silently zeroed
// the bound and returned an aggregate over all history.
func TestAuditStrictParamRejects(t *testing.T) {
	registerTestCodes(t)
	db, _ := sql.Open("sqlite", ":memory:")
	store, err := NewSQLiteStore(db, "audit_strict")
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store,
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	h := NewReader()

	cases := []struct{ url, param string }{
		{"/audit?offset=12a3", "offset"},
		{"/audit?offset=-1", "offset"},
		{"/audit?after=12a3", "after"},
		{"/audit?since=2026-08-01", "since"}, // date-only, not RFC3339
		{"/audit?until=notatime", "until"},
		{"/topology?since=2026-08-01", "since"},
		{"/topology?until=nope", "until"},
	}
	for _, c := range cases {
		if code := status(t, h, c.url); code != 422 {
			t.Errorf("%s -> %d, want 422 (%s param)", c.url, code, c.param)
		}
	}
	// Well-formed values still work.
	for _, url := range []string{
		"/audit", "/audit?offset=0", "/audit?after=1", "/audit?since=2026-08-01T00:00:00Z",
		"/topology?since=2026-08-01T00:00:00Z",
	} {
		if code := status(t, h, url); code != 200 {
			t.Errorf("%s -> %d, want 200", url, code)
		}
	}
}

func TestSearchLimitStrict(t *testing.T) {
	registerTestCodes(t)
	db, _ := sql.Open("sqlite", ":memory:")
	ss, err := NewStreamStore(db, "syslog_strict")
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SearchEnabled: true, SyslogStore: ss}); err != nil {
		t.Fatal(err)
	}
	h := NewReader()

	base := "/search?q=x&since=2026-01-01T00:00:00Z"
	for _, bad := range []string{"abc", "0", "-1", "500"} {
		if code := status(t, h, base+"&limit="+bad); code != 422 {
			t.Errorf("/search limit=%s -> %d, want 422", bad, code)
		}
	}
	if code := status(t, h, base+"&limit=100"); code != 200 {
		t.Errorf("/search limit=100 -> %d, want 200", code)
	}
	// /sys?q= path shares the helper.
	sysBase := "/sys?q=x&since=2026-01-01T00:00:00Z"
	for _, bad := range []string{"abc", "500"} {
		if code := status(t, h, sysBase+"&limit="+bad); code != 422 {
			t.Errorf("/sys?q= limit=%s -> %d, want 422", bad, code)
		}
	}
}

// FR3-3 — free-text q= is sys-only; the api endpoint rejects it (400) rather
// than silently dropping it.
func TestApiQParamRejected(t *testing.T) {
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	h := NewReader()
	if code := status(t, h, "/api?q=foo"); code != 400 {
		t.Errorf("/api?q=foo -> %d, want 400", code)
	}
	if code := status(t, h, "/api?q="); code != 400 {
		t.Errorf("/api?q= (empty, present) -> %d, want 400", code)
	}
	if code := status(t, h, "/api"); code != 200 {
		t.Errorf("/api (no q) -> %d, want 200", code)
	}
}

// FR5-r — a capacity-0 ring drops on push instead of panicking (parity with
// Python's deque(maxlen=0)).
func TestRingCapacityZeroDrops(t *testing.T) {
	rb := newRingBuffer[int](0)
	rb.Push(1) // must not panic
	rb.Push(2)
	if rb.Len() != 0 {
		t.Fatalf("cap-0 ring Len=%d, want 0", rb.Len())
	}
	if len(rb.All()) != 0 {
		t.Fatalf("cap-0 ring All()=%v, want empty", rb.All())
	}
}

// M1 — OpenStreamStore sets synchronous=NORMAL on every pooled connection (not
// just the migrate connection).
func TestOpenStreamStorePragmaAllConns(t *testing.T) {
	s, err := OpenStreamStore(t.TempDir()+"/streams.db", "sys_log")
	if err != nil {
		t.Fatal(err)
	}
	s.db.SetMaxOpenConns(4)
	ctx := context.Background()
	var held []*sql.Conn
	for i := 0; i < 4; i++ {
		c, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	for i, c := range held {
		var syncv int
		var jm string
		if err := c.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&syncv); err != nil {
			t.Fatal(err)
		}
		if err := c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&jm); err != nil {
			t.Fatal(err)
		}
		if syncv != 1 || jm != "wal" {
			t.Fatalf("conn %d synchronous=%d journal_mode=%q, want 1/wal", i, syncv, jm)
		}
	}
	for _, c := range held {
		c.Close()
	}
}

// M4 — a non-string request_id is treated as missing and gets a sentinel
// (parity with Python), not stashed as-is.
func TestStampRequestIDNonString(t *testing.T) {
	tr := NewTransport(10)
	tr.serviceID = "svc"
	row := map[string]any{"request_id": 123, "event": "x"}
	tr.stampRequestID(row)
	rid, ok := row["request_id"].(string)
	if !ok || !IsSentinel(rid) {
		t.Fatalf("non-string request_id -> %v (%T), want a sentinel string", row["request_id"], row["request_id"])
	}
	real := map[string]any{"request_id": "real-abc"}
	tr.stampRequestID(real)
	if real["request_id"] != "real-abc" {
		t.Fatalf("real string id changed: %v", real["request_id"])
	}
}

// FR5-9 — /audit reports both pagination models: offset (total/limit/offset)
// and cursor (next_after, forward = older rows).
func TestAuditDualPaginationRegression(t *testing.T) {
	registerTestCodes(t)
	db, _ := sql.Open("sqlite", ":memory:")
	store, err := NewSQLiteStore(db, "audit_pag_reg")
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestID(context.Background(), "rq")
	for i := 0; i < 5; i++ {
		if _, err := Emit(ctx, "USER_CREATED", Target("u"), Actor("a", "user")); err != nil {
			t.Fatal(err)
		}
	}
	h := NewReader()
	get := func(url string) map[string]any {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
		var m map[string]any
		json.Unmarshal(rr.Body.Bytes(), &m)
		return m
	}
	seqs := func(m map[string]any) []int {
		var out []int
		for _, r := range m["rows"].([]any) {
			out = append(out, int(r.(map[string]any)["monotonic_seq"].(float64)))
		}
		return out
	}
	p1 := get("/audit?limit=2")
	for _, k := range []string{"total", "limit", "offset", "next_after"} {
		if _, ok := p1[k]; !ok {
			t.Fatalf("/audit response missing %q: %v", k, p1)
		}
	}
	if p1["total"].(float64) != 5 {
		t.Fatalf("total=%v want 5", p1["total"])
	}
	var walk [][]int
	page := p1
	for i := 0; i < 6 && len(page["rows"].([]any)) > 0; i++ {
		walk = append(walk, seqs(page))
		if page["next_after"] == nil {
			break
		}
		page = get("/audit?limit=2&after=" + strconv.Itoa(int(page["next_after"].(float64))))
	}
	if got := toStr(walk); got != "[[5 4] [3 2] [1]]" {
		t.Fatalf("cursor walk = %s, want [[5 4] [3 2] [1]]", got)
	}
	if got := toStr([][]int{seqs(get("/audit?limit=2&offset=2"))}); got != "[[3 2]]" {
		t.Fatalf("offset=2 seqs = %s, want [[3 2]]", got)
	}
}

func toStr(v [][]int) string {
	b, _ := json.Marshal(v)
	s := string(b)
	// render like Go's %v ("[[5 4] [3 2] [1]]") for a stable compare
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch c {
		case ',':
			out = append(out, ' ')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
