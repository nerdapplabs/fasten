package fasten

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Chain checkpoints (spec §9): rows checked against a node's published
// latest seq and hash show a cut-off tail and a full re-seal.

func cpChain(n int, node, target string) []Row {
	rows := make([]Row, 0, n)
	prev := "genesis"
	for i := 1; i <= n; i++ {
		r := cpRow(i, node, target)
		r = Seal(prev, r)
		rows = append(rows, r)
		prev = r.Hash
	}
	return rows
}

func cpRow(seq int, node, target string) Row {
	id := fmt.Sprintf("evt-%s-%d-%s", node, seq, target)
	return Row{
		WireVersion: "1", ID: id, OriginID: id, MonotonicSeq: int64(seq),
		Timestamp: time.Date(2026, 6, 15, 10, 30, seq%60, 0, time.UTC),
		Code:      "USER_CREATED", Action: "create", Severity: SevInfo,
		ServiceID: "svc", SourceNodeID: node, Actor: "a", ActorKind: "user",
		Target: target, Category: "account", Domain: "user", Method: "sdk",
		RequestID: "req-" + itoa(seq), Detail: map[string]any{"k": "v"},
	}
}

func cpOf(r Row) Checkpoint {
	return Checkpoint{SourceNodeID: r.SourceNodeID, MonotonicSeq: r.MonotonicSeq, Hash: r.Hash, AnchoredAt: "2026-06-15T11:00:00.000000Z"}
}

func wantBreak(t *testing.T, res VerifyResult, seq int64, reason string) {
	t.Helper()
	if res.OK || res.FirstBreakAt != seq || res.Reason != reason {
		t.Fatalf("got %+v, want a break at %d: %q", res, seq, reason)
	}
}

func TestCheckpointMatchingTheTipVerifies(t *testing.T) {
	rows := cpChain(5, "node-1", "u1")
	if res := VerifyChainWithCheckpoints(rows, []Checkpoint{cpOf(rows[1]), cpOf(rows[4])}, CheckpointOptions{}); !res.OK {
		t.Fatalf("got %+v", res)
	}
}

func TestCheckpointCutOffTailBreaksAfterTheLastRow(t *testing.T) {
	rows := cpChain(10, "node-1", "u1")
	if !VerifyChain(rows[:6]).OK {
		t.Fatal("a cut-off chain verifies on its own")
	}
	wantBreak(t, VerifyChainWithCheckpoints(rows[:6], []Checkpoint{cpOf(rows[9])}, CheckpointOptions{}), 7,
		"node 'node-1': chain ends at seq 6 before checkpoint at seq 10")
}

func TestCheckpointResealedChainFails(t *testing.T) {
	rows := cpChain(5, "node-1", "u1")
	resealed := cpChain(5, "node-1", "u2")
	if !VerifyChain(resealed).OK {
		t.Fatal("a re-sealed chain verifies on its own")
	}
	wantBreak(t, VerifyChainWithCheckpoints(resealed, []Checkpoint{cpOf(rows[4])}, CheckpointOptions{}), 5,
		"row "+resealed[4].ID+": hash differs from checkpoint at seq 5")
}

func TestCheckpointBelowTheOldestRowFailsAWholeChainVerify(t *testing.T) {
	rows := cpChain(10, "node-1", "u1")
	cps := []Checkpoint{cpOf(rows[1]), cpOf(rows[9])}
	wantBreak(t, VerifyChainWithCheckpoints(rows[4:], cps, CheckpointOptions{}), 5,
		"node 'node-1': rows start at seq 5, after the checkpoint at seq 2")
	if res := VerifyChainWithCheckpoints(rows[4:], cps, CheckpointOptions{Partial: true}); !res.OK {
		t.Fatalf("got %+v", res)
	}
}

func TestCheckpointRowsResealedAboveAnOldCheckpointFailAfterTheNextPublish(t *testing.T) {
	// Every row deleted and edited copies re-sealed from seq 21, then the
	// next publish checkpoints the new tip. The checkpoint at 20 still fails.
	rows := cpChain(20, "node-1", "u1")
	resealed := cpChainFrom(21, 10, "node-1", "u2")
	cps := []Checkpoint{cpOf(rows[19]), cpOf(resealed[9])}
	if !VerifyChain(resealed).OK {
		t.Fatal("a re-sealed chain verifies on its own")
	}
	wantBreak(t, VerifyChainWithCheckpoints(resealed, cps, CheckpointOptions{}), 21,
		"node 'node-1': rows start at seq 21, after the checkpoint at seq 20")
	if res := VerifyChainWithCheckpoints(resealed, cps, CheckpointOptions{Partial: true}); !res.OK {
		t.Fatalf("got %+v", res)
	}
}

func TestCheckpointPurgeVerifiesWithTheCheckpointsSinceIt(t *testing.T) {
	rows := cpChain(10, "node-1", "u1")
	cps := []Checkpoint{cpAt(rows[1], "2026-06-15T11:00:00.000000Z"), cpAt(rows[9], "2026-06-15T12:00:00.000000Z")}
	if VerifyChainWithCheckpoints(rows[4:], cps, CheckpointOptions{}).OK {
		t.Fatal("a checkpoint from before the purge passed")
	}
	kept, err := CheckpointsSince(cps, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyChainWithCheckpoints(rows[4:], kept, CheckpointOptions{}); !res.OK {
		t.Fatalf("got %+v", res)
	}
}

func TestCheckpointMissingRowInsideTheChainBreaksThere(t *testing.T) {
	sealed := cpChain(7, "node-1", "u1")
	var rows []Row
	for _, seq := range []int{1, 2} {
		r := cpRow(seq, "node-1", "u1")
		rows = append(rows, r)
	}
	rows = append(rows, sealed[4:]...)
	if !VerifyChain(rows).OK {
		t.Fatal("rows verify on their own")
	}
	wantBreak(t, VerifyChainWithCheckpoints(rows, []Checkpoint{cpOf(sealed[2])}, CheckpointOptions{}), 3,
		"node 'node-1': no row at checkpointed seq 3")
}

// cpChainFrom is cpChain with seqs from start, sealed from genesis.
func cpChainFrom(start, n int, node, target string) []Row {
	rows := make([]Row, 0, n)
	prev := "genesis"
	for i := start; i < start+n; i++ {
		r := Seal(prev, cpRow(i, node, target))
		rows = append(rows, r)
		prev = r.Hash
	}
	return rows
}

func TestCheckpointChainResealedAboveTheNewestFails(t *testing.T) {
	rows := cpChain(10, "node-1", "u1")
	resealed := cpChainFrom(11, 10, "node-1", "u2")
	if !VerifyChain(resealed).OK {
		t.Fatal("a re-sealed chain verifies on its own")
	}
	wantBreak(t, VerifyChainWithCheckpoints(resealed, []Checkpoint{cpOf(rows[4]), cpOf(rows[9])}, CheckpointOptions{}), 11,
		"node 'node-1': rows start at seq 11, after the checkpoint at seq 5")
}

func TestCheckpointedNodeWithNoRowsFails(t *testing.T) {
	one, two := cpChain(3, "node-1", "u1"), cpChain(5, "node-2", "u1")
	wantBreak(t, VerifyChainWithCheckpoints(one, []Checkpoint{cpOf(one[2]), cpOf(two[1]), cpOf(two[4])}, CheckpointOptions{}), 5,
		"node 'node-2': no rows, but checkpointed at seq 5")
	res := VerifyChainWithCheckpoints(nil, []Checkpoint{cpOf(two[4])}, CheckpointOptions{})
	wantBreak(t, res, 5, "node 'node-2': no rows, but checkpointed at seq 5")
	if res.TotalRows != 0 {
		t.Fatalf("got %+v", res)
	}
}

func TestCheckpointPartialSkipsCheckpointsOutsideTheRows(t *testing.T) {
	rows := cpChain(10, "node-1", "u1")
	other := cpChain(3, "node-2", "u1")
	resealed := cpChainFrom(11, 10, "node-1", "u2")
	cps := []Checkpoint{cpOf(rows[9]), cpOf(other[2])}
	partial := CheckpointOptions{Partial: true}
	for _, batch := range [][]Row{resealed, nil, rows[4:], cpChain(3, "node-1", "u1")[:0]} {
		if res := VerifyChainWithCheckpoints(batch, cps, partial); !res.OK {
			t.Fatalf("got %+v", res)
		}
	}
	// An older page: the checkpoint above it says nothing about rows 3 to 6.
	if res := VerifyChainWithCheckpoints(rows[2:6], cps, partial); !res.OK {
		t.Fatalf("older page: got %+v", res)
	}
	// The whole chain cut off at 6 is still caught.
	wantBreak(t, VerifyChainWithCheckpoints(rows[:6], cps[:1], CheckpointOptions{}), 7,
		"node 'node-1': chain ends at seq 6 before checkpoint at seq 10")
}

func TestCheckpointLowestBreakAcrossNodes(t *testing.T) {
	a, b := cpChain(10, "node-a", "u1"), cpChain(10, "node-b", "u1")
	rows := append(append([]Row{}, a[:8]...), b[:3]...)
	wantBreak(t, VerifyChainWithCheckpoints(rows, []Checkpoint{cpOf(a[9]), cpOf(b[9])}, CheckpointOptions{}), 4,
		"node 'node-b': chain ends at seq 3 before checkpoint at seq 10")
}

func TestCheckpointChainBreakBelowItWins(t *testing.T) {
	rows := cpChain(10, "node-1", "u1")
	cut := append([]Row{}, rows[:6]...)
	cut[1].Target = "u-edited"
	res := VerifyChainWithCheckpoints(cut, []Checkpoint{cpOf(rows[9])}, CheckpointOptions{})
	if res.FirstBreakAt != 2 || !strings.Contains(res.Reason, "hash mismatch") {
		t.Fatalf("got %+v", res)
	}
}

func TestFileCheckpointSinkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.jsonl")
	sink := FileCheckpointSink{Path: path}
	first := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0]), cpOf(cpChain(2, "node-1", "u1")[1])}
	second := []Checkpoint{cpOf(cpChain(1, "node-2", "u1")[0])}
	ctx := context.Background()
	for _, batch := range [][]Checkpoint{first, second, nil} {
		if err := sink.Publish(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LoadCheckpoints(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(first, second...); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	raw, _ := os.ReadFile(path)
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(string(raw), "\n", 2)[0]), &line); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"source_node_id", "monotonic_seq", "hash", "anchored_at"} {
		if _, ok := line[k]; !ok || len(line) != 4 {
			t.Fatalf("line %v lacks %s", line, k)
		}
	}
}

func TestLoadCheckpointsRejectsALineThatIsNotACheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	for _, body := range []string{
		`{"source_node_id":"n","monotonic_seq":"1","hash":"h","anchored_at":"t"}`,
		`{"source_node_id":"n","hash":"h","anchored_at":"t"}`,
		`{"source_node_id":"n","monotonic_seq":1,"hash":"h","anchored_at":"t","x":1}`,
		`{"source_node_id":"n","Monotonic_Seq":1,"hash":"h","anchored_at":"t"}`,
		`{"source_node_id":null,"monotonic_seq":1,"hash":"h","anchored_at":"t"}`,
		`[]`,
		`{"source_node_id":"n","monot` + "\n" + `{"source_node_id":"n","monotonic_seq":1,"hash":"h","anchored_at":"t"}`,
	} {
		if err := os.WriteFile(path, []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCheckpoints(path); err == nil {
			t.Fatalf("loaded %s", body)
		}
	}
}

func TestLoadCheckpointsUnfinishedLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.jsonl")
	cps := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0]), cpOf(cpChain(2, "node-1", "u1")[1])}
	if err := (FileCheckpointSink{Path: path}).Publish(context.Background(), cps); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	// A complete last line without a newline is read.
	if err := os.WriteFile(path, bytes.TrimSuffix(raw, []byte("\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadCheckpoints(path); err != nil || !reflect.DeepEqual(got, cps) {
		t.Fatalf("got %+v, %v", got, err)
	}
	// An unfinished one is skipped and reported.
	if err := os.WriteFile(path, append(raw, `{"source_node_id":"node-1","monot`...), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCheckpoints(path)
	if !errors.Is(err, ErrPartialLastLine) || !reflect.DeepEqual(got, cps) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestFileCheckpointSinkDropsAnUnfinishedLastLine(t *testing.T) {
	ctx := context.Background()
	first := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0]), cpOf(cpChain(2, "node-1", "u1")[1])}
	second := []Checkpoint{cpOf(cpChain(1, "node-2", "u1")[0])}
	torn := `{"source_node_id":"node-1","monot`
	var whole bytes.Buffer
	enc := json.NewEncoder(&whole)
	for _, cp := range first {
		if err := enc.Encode(cp); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, body string
		want       []Checkpoint
	}{
		{"after complete lines", whole.String() + torn, append(slices.Clone(first), second...)},
		{"only an unfinished line", torn, second},
		{"complete last line without a newline", strings.TrimSuffix(whole.String(), "\n"), append(slices.Clone(first), second...)},
		{"empty file", "", second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cp.jsonl")
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := (FileCheckpointSink{Path: path}).Publish(ctx, second); err != nil {
				t.Fatal(err)
			}
			if got, err := LoadCheckpoints(path); err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func cpAt(r Row, at string) Checkpoint {
	cp := cpOf(r)
	cp.AnchoredAt = at
	return cp
}

func TestCheckpointsSinceDropsAFullyPurgedNodesCheckpoints(t *testing.T) {
	// node-2's rows were all purged at 12:00; node-1 was checkpointed again after.
	one, two := cpChain(5, "node-1", "u1"), cpChain(3, "node-2", "u1")
	cps := []Checkpoint{
		cpAt(one[2], "2026-06-15T11:00:00.000000Z"),
		cpAt(two[2], "2026-06-15T11:59:00.000000Z"),
		cpAt(one[4], "2026-06-15T12:00:00.000000Z"),
	}
	if VerifyChainWithCheckpoints(one, cps, CheckpointOptions{}).OK {
		t.Fatal("a purged node's checkpoint passed")
	}
	kept, err := CheckpointsSince(cps, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	if err != nil || !reflect.DeepEqual(kept, cps[2:]) {
		t.Fatalf("got %+v, %v", kept, err)
	}
	if res := VerifyChainWithCheckpoints(one, kept, CheckpointOptions{}); !res.OK {
		t.Fatalf("got %+v", res)
	}
}

func TestCheckpointsSinceKeepsARecentCheckpointOfANodeWithNoRows(t *testing.T) {
	one, two := cpChain(5, "node-1", "u1"), cpChain(3, "node-2", "u1")
	cps := []Checkpoint{cpAt(two[2], "2026-06-15T12:30:00.000000Z"), cpAt(one[4], "2026-06-15T12:30:00.000000Z")}
	cutoff := time.Date(2026, 6, 15, 14, 0, 0, 0, time.FixedZone("", 2*3600))
	kept, err := CheckpointsSince(cps, cutoff)
	if err != nil || !reflect.DeepEqual(kept, cps) {
		t.Fatalf("got %+v, %v", kept, err)
	}
	wantBreak(t, VerifyChainWithCheckpoints(one, kept, CheckpointOptions{}), 3,
		"node 'node-2': no rows, but checkpointed at seq 3")
}

func TestCheckpointsSinceRejectsANonCanonicalAnchoredAt(t *testing.T) {
	cps := []Checkpoint{cpAt(cpChain(1, "node-1", "u1")[0], "2026-06-15T12:30:00Z")}
	if _, err := CheckpointsSince(cps, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted a non-canonical anchored_at")
	}
}

func TestHTTPCheckpointSinkRedirectFails(t *testing.T) {
	cps := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0])}
	for _, code := range []int{301, 302, 303, 307, 308} {
		var posts, gets int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				posts++
				http.Redirect(w, r, "/elsewhere", code)
				return
			}
			gets++
		}))
		for _, sink := range []HTTPCheckpointSink{{URL: srv.URL}, {URL: srv.URL, Client: &http.Client{}}} {
			err := sink.Publish(context.Background(), cps)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", code)) {
				t.Fatalf("%d: got %v", code, err)
			}
		}
		srv.Close()
		if posts != 2 || gets != 0 {
			t.Fatalf("%d: %d posts, %d gets", code, posts, gets)
		}
	}
}

func TestHTTPCheckpointSinkDefaultTimeout(t *testing.T) {
	if c := (HTTPCheckpointSink{}).client(); c.Timeout != 10*time.Second || c == http.DefaultClient {
		t.Fatalf("got %+v", c)
	}
}

func TestHTTPCheckpointSinkSendsUserinfoAsBasicAuth(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	cps := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0])}
	for _, u := range []string{"http://user:p%40ss@" + host, srv.URL} {
		if err := (HTTPCheckpointSink{URL: u}).Publish(context.Background(), cps); err != nil {
			t.Fatal(err)
		}
	}
	// user:p@ss
	if want := []string{"Basic dXNlcjpwQHNz", ""}; !slices.Equal(auth, want) {
		t.Fatalf("got %q, want %q", auth, want)
	}
}

func TestHTTPCheckpointSinkErrorsLeaveOutUserinfoAndQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	host := strings.TrimPrefix(srv.URL, "http://")
	raw := "http://user:pw-123@" + host + "/checkpoints?token=tok-456"
	cps := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0])}
	sink := HTTPCheckpointSink{URL: raw}
	err := sink.Publish(context.Background(), cps)
	if want := "checkpoint sink " + srv.URL + "/checkpoints: HTTP 500"; err == nil || err.Error() != want {
		t.Fatalf("got %v, want %s", err, want)
	}
	srv.Close()
	for _, url := range []string{raw, "http://user:pw-123@" + host + "/%zz?token=tok-456"} {
		err = HTTPCheckpointSink{URL: url}.Publish(context.Background(), cps)
		if err == nil || strings.Contains(err.Error(), "pw-123") || strings.Contains(err.Error(), "tok-456") {
			t.Fatalf("got %v", err)
		}
	}
}

func TestHTTPCheckpointSink(t *testing.T) {
	var gotType string
	var gotBody []Checkpoint
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = nil
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	cps := []Checkpoint{cpOf(cpChain(1, "node-1", "u1")[0])}
	sink := HTTPCheckpointSink{URL: srv.URL}
	if err := sink.Publish(context.Background(), cps); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/json" || !reflect.DeepEqual(gotBody, cps) {
		t.Fatalf("server got %q %+v", gotType, gotBody)
	}
	status = http.StatusInternalServerError
	if err := sink.Publish(context.Background(), cps); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("got %v, want an HTTP 500 error", err)
	}
}

// cpStore is what the store-backed checkpoint cases need from a store.
type cpStore interface {
	CheckpointStore
	AllocateAndInsertOriginated(ctx context.Context, row Row) (Row, error)
	InsertOriginated(ctx context.Context, row Row) error
	ChainTail(ctx context.Context, sourceNodeID string, limit int) ([]Row, error)
}

// runCheckpointStoreCases runs the store-backed cases against fresh stores
// from open, which also returns the store's db and table.
func runCheckpointStoreCases(t *testing.T, open func(t *testing.T) (cpStore, *sql.DB, string)) {
	ctx := context.Background()
	emit := func(t *testing.T, s cpStore, n int, node, target string) []Row {
		t.Helper()
		var out []Row
		for i := 1; i <= n; i++ {
			r := cpRow(i, node, target)
			r.MonotonicSeq = 0
			sealed, err := s.AllocateAndInsertOriginated(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, sealed)
		}
		return out
	}
	tail := func(t *testing.T, s cpStore) []Row {
		t.Helper()
		rows, err := s.ChainTail(ctx, "node-1", 1000)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	take := func(t *testing.T, s cpStore) []Checkpoint {
		t.Helper()
		cps, err := TakeCheckpoints(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		return cps
	}
	exec := func(t *testing.T, db *sql.DB, q string) {
		t.Helper()
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("published checkpoint verifies", func(t *testing.T) {
		s, _, _ := open(t)
		emit(t, s, 4, "node-1", "u1")
		path := filepath.Join(t.TempDir(), "cp.jsonl")
		cps, err := PublishCheckpoints(ctx, s, FileCheckpointSink{Path: path})
		if err != nil || len(cps) != 1 || cps[0].MonotonicSeq != 4 {
			t.Fatalf("got %+v, %v", cps, err)
		}
		if _, err := parseCanonicalTS(cps[0].AnchoredAt); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadCheckpoints(path)
		if err != nil {
			t.Fatal(err)
		}
		if res := VerifyChainWithCheckpoints(tail(t, s), loaded, CheckpointOptions{}); !res.OK {
			t.Fatalf("got %+v", res)
		}
	})

	t.Run("rows deleted from the end", func(t *testing.T) {
		s, db, table := open(t)
		emit(t, s, 8, "node-1", "u1")
		cps := take(t, s)
		exec(t, db, fmt.Sprintf("DELETE FROM %s WHERE monotonic_seq > 5", table))
		rows := tail(t, s)
		if !VerifyChain(rows).OK {
			t.Fatal("cut chain verifies on its own")
		}
		wantBreak(t, VerifyChainWithCheckpoints(rows, cps, CheckpointOptions{}), 6,
			"node 'node-1': chain ends at seq 5 before checkpoint at seq 8")
	})

	t.Run("resealed from genesis", func(t *testing.T) {
		s, db, table := open(t)
		emit(t, s, 5, "node-1", "u1")
		cps := take(t, s)
		exec(t, db, fmt.Sprintf("DELETE FROM %s", table))
		emit(t, s, 6, "node-1", "u-rewritten")
		rows := tail(t, s)
		if !VerifyChain(rows).OK {
			t.Fatal("re-sealed chain verifies on its own")
		}
		wantBreak(t, VerifyChainWithCheckpoints(rows, cps, CheckpointOptions{}), 5,
			"row "+rows[4].ID+": hash differs from checkpoint at seq 5")
	})

	t.Run("latest sealed row per node", func(t *testing.T) {
		s, _, _ := open(t)
		a := emit(t, s, 3, "node-a", "u1")
		b := emit(t, s, 2, "node-b", "u1")
		for _, r := range []Row{cpRow(4, "node-a", "ux"), cpRow(1, "node-c", "u1")} {
			if err := s.InsertOriginated(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		cps := take(t, s)
		if len(cps) != 2 || cps[0].SourceNodeID != "node-a" || cps[0].MonotonicSeq != 3 || cps[0].Hash != a[2].Hash ||
			cps[1].SourceNodeID != "node-b" || cps[1].MonotonicSeq != 2 || cps[1].Hash != b[1].Hash ||
			cps[0].AnchoredAt != cps[1].AnchoredAt {
			t.Fatalf("got %+v", cps)
		}
	})

	t.Run("empty store", func(t *testing.T) {
		s, _, _ := open(t)
		if cps := take(t, s); len(cps) != 0 {
			t.Fatalf("got %+v", cps)
		}
	})
}

func TestCheckpointsSQLite(t *testing.T) {
	runCheckpointStoreCases(t, func(t *testing.T) (cpStore, *sql.DB, string) {
		s := ingestStore(t)
		return s, s.db, s.table
	})
}

// spec/checkpoint-vectors.json is generated by Python
// (scripts/gen_checkpoint_vectors.py); Go must give the same results.
func TestCheckpointVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/checkpoint-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Label       string       `json:"label"`
			Partial     bool         `json:"partial"`
			Rows        []Row        `json:"rows"`
			Checkpoints []Checkpoint `json:"checkpoints"`
			Expected    struct {
				OK           bool    `json:"ok"`
				FirstBreakAt *int64  `json:"first_break_at"`
				Reason       *string `json:"reason"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 8 {
		t.Fatalf("only %d cases", len(file.Cases))
	}
	for _, c := range file.Cases {
		t.Run(c.Label, func(t *testing.T) {
			res := VerifyChainWithCheckpoints(c.Rows, c.Checkpoints, CheckpointOptions{Partial: c.Partial})
			var at int64
			if c.Expected.FirstBreakAt != nil {
				at = *c.Expected.FirstBreakAt
			}
			reason := ""
			if c.Expected.Reason != nil {
				reason = *c.Expected.Reason
			}
			if res.OK != c.Expected.OK || res.FirstBreakAt != at || res.Reason != reason {
				t.Fatalf("got %+v, want %+v", res, c.Expected)
			}
		})
	}
}
