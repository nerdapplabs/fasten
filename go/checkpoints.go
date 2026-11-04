package fasten

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"
)

// Checkpoint records a node's latest sealed row (spec §9). Published
// somewhere the store's operator cannot rewrite, it lets
// VerifyChainWithCheckpoints detect a chain cut short at the end, or
// re-sealed from genesis. AnchoredAt is a canonical UTC timestamp.
type Checkpoint struct {
	SourceNodeID string `json:"source_node_id"`
	MonotonicSeq int64  `json:"monotonic_seq"`
	Hash         string `json:"hash"`
	AnchoredAt   string `json:"anchored_at"`
}

// CheckpointSink is where checkpoints are published.
type CheckpointSink interface {
	Publish(ctx context.Context, checkpoints []Checkpoint) error
}

// FileCheckpointSink appends one JSON line per checkpoint to Path and
// fsyncs it.
type FileCheckpointSink struct {
	Path string
}

// Publish appends checkpoints to the file.
func (s FileCheckpointSink) Publish(_ context.Context, checkpoints []Checkpoint) error {
	if len(checkpoints) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, cp := range checkpoints {
		if err := enc.Encode(cp); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// HTTPCheckpointSink POSTs the checkpoints as one JSON array to URL. Client
// nil means a client with a 10 s timeout; the context also bounds the
// request. Redirects are not followed, whatever the client, and errors name
// the URL without userinfo or query.
type HTTPCheckpointSink struct {
	URL    string
	Client *http.Client
}

// Publish sends checkpoints and returns an error unless the response is 2xx.
func (s HTTPCheckpointSink) Publish(ctx context.Context, checkpoints []Checkpoint) error {
	if len(checkpoints) == 0 {
		return nil
	}
	body, err := json.Marshal(checkpoints)
	if err != nil {
		return err
	}
	where := redactURL(s.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("checkpoint sink %s: invalid url", where)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		// A *url.Error names the request URL with its query.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return fmt.Errorf("checkpoint sink %s: %w", where, err)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("checkpoint sink %s: HTTP %d", where, resp.StatusCode)
	}
	return nil
}

// client is a copy of s.Client, or one with a 10 s timeout, that does not
// follow redirects: a client follows a 301-303 on POST as a GET without the
// body.
func (s HTTPCheckpointSink) client() *http.Client {
	c := http.Client{Timeout: 10 * time.Second}
	if s.Client != nil {
		c = *s.Client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// redactURL is raw as scheme://host[:port]/path, for error messages: no
// userinfo, query or fragment.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(invalid url)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// CheckpointStore is what TakeCheckpoints reads: each node's sealed row
// with the highest monotonic_seq, by node id. SQLiteStore and PostgresStore
// implement it.
type CheckpointStore interface {
	ChainTips(ctx context.Context) ([]Row, error)
}

// TakeCheckpoints returns one checkpoint per node in store with a sealed
// row, by node id.
func TakeCheckpoints(ctx context.Context, store CheckpointStore) ([]Checkpoint, error) {
	tips, err := store.ChainTips(ctx)
	if err != nil {
		return nil, err
	}
	now := canonicalNow()
	var out []Checkpoint
	for _, tip := range tips {
		if n := len(out); n > 0 && out[n-1].SourceNodeID == tip.SourceNodeID {
			continue // two rows at one seq; VerifyChain reports that
		}
		out = append(out, Checkpoint{SourceNodeID: tip.SourceNodeID, MonotonicSeq: tip.MonotonicSeq, Hash: tip.Hash, AnchoredAt: now})
	}
	return out, nil
}

// PublishCheckpoints takes checkpoints of store, publishes them to sink and
// returns them.
func PublishCheckpoints(ctx context.Context, store CheckpointStore, sink CheckpointSink) ([]Checkpoint, error) {
	checkpoints, err := TakeCheckpoints(ctx, store)
	if err != nil {
		return nil, err
	}
	if err := sink.Publish(ctx, checkpoints); err != nil {
		return nil, err
	}
	return checkpoints, nil
}

// ErrPartialLastLine is returned by LoadCheckpoints, with the checkpoints
// before it, when the file's last line has no newline and is not valid
// JSON, as a crash mid-append leaves it. Check it with errors.Is to go on
// with those checkpoints. Python logs a warning for it instead.
var ErrPartialLastLine = errors.New("checkpoint file ends in an unfinished line")

// LoadCheckpoints reads back a file written by FileCheckpointSink. Blank
// lines are skipped. A line that is not a checkpoint, with exactly the four
// fields, fails the load, except an unfinished last line: see
// ErrPartialLastLine.
func LoadCheckpoints(path string) ([]Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(data, []byte("\n"))
	// The text after the last newline; empty when the file ends with one.
	last := lines[len(lines)-1]
	lines = lines[:len(lines)-1]
	var out []Checkpoint
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		cp, err := parseCheckpoint(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, cp)
	}
	if len(bytes.TrimSpace(last)) > 0 {
		if !json.Valid(last) {
			return out, fmt.Errorf("%s: %w", path, ErrPartialLastLine)
		}
		cp, err := parseCheckpoint(last)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, cp)
	}
	return out, nil
}

// parseCheckpoint decodes one line. Keys must match exactly, case included,
// and no other key may appear, as in Python.
func parseCheckpoint(line []byte) (Checkpoint, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return Checkpoint{}, fmt.Errorf("not a checkpoint: %w", err)
	}
	var cp Checkpoint
	targets := map[string]any{
		"source_node_id": &cp.SourceNodeID, "monotonic_seq": &cp.MonotonicSeq,
		"hash": &cp.Hash, "anchored_at": &cp.AnchoredAt,
	}
	if len(fields) != len(targets) {
		return Checkpoint{}, fmt.Errorf("not a checkpoint: %s", line)
	}
	for key, target := range targets {
		v, ok := fields[key]
		// Unmarshal leaves a field unset on null rather than failing.
		if !ok || string(v) == "null" || json.Unmarshal(v, target) != nil {
			return Checkpoint{}, fmt.Errorf("not a checkpoint: %s", line)
		}
	}
	return cp, nil
}

// checkpointBreak checks rows, one copy per id, against checkpoints and
// returns the lowest-seq break, or nil. Checkpoints are taken by node, then
// seq, as in Python, so both report the same break. Unless partial, each
// node's newest checkpoint must fall within its rows.
func checkpointBreak(rows []Row, checkpoints []Checkpoint, partial bool) *VerifyResult {
	if len(checkpoints) == 0 {
		return nil
	}
	byNode := map[string][]Row{}
	for _, row := range rows {
		byNode[row.SourceNodeID] = append(byNode[row.SourceNodeID], row)
	}
	newest := map[string]int64{}
	for _, cp := range checkpoints {
		if seq, ok := newest[cp.SourceNodeID]; !ok || cp.MonotonicSeq > seq {
			newest[cp.SourceNodeID] = cp.MonotonicSeq
		}
	}
	sorted := slices.Clone(checkpoints)
	slices.SortStableFunc(sorted, func(a, b Checkpoint) int {
		return cmp.Or(cmp.Compare(a.SourceNodeID, b.SourceNodeID), cmp.Compare(a.MonotonicSeq, b.MonotonicSeq))
	})
	var first *VerifyResult
	for _, cp := range sorted {
		mustCover := !partial && cp.MonotonicSeq == newest[cp.SourceNodeID]
		var found *VerifyResult
		if nodeRows := byNode[cp.SourceNodeID]; len(nodeRows) > 0 {
			found = checkpointMismatch(nodeRows, cp, mustCover)
		} else if mustCover {
			found = &VerifyResult{FirstBreakAt: cp.MonotonicSeq, Reason: fmt.Sprintf(
				"node '%s': no rows, but checkpointed at seq %d", cp.SourceNodeID, cp.MonotonicSeq)}
		}
		if found != nil && (first == nil || found.FirstBreakAt < first.FirstBreakAt) {
			first = found
		}
	}
	return first
}

// checkpointMismatch checks one node's rows against a checkpoint of that
// node; nil if they agree. A checkpoint older than the oldest row is
// skipped unless newest says it must be covered.
func checkpointMismatch(rows []Row, cp Checkpoint, newest bool) *VerifyResult {
	seq := cp.MonotonicSeq
	lowest, highest := rows[0].MonotonicSeq, rows[0].MonotonicSeq
	var at []Row
	for _, row := range rows {
		lowest, highest = min(lowest, row.MonotonicSeq), max(highest, row.MonotonicSeq)
		if row.MonotonicSeq == seq {
			if row.Hash == cp.Hash {
				return nil
			}
			at = append(at, row)
		}
	}
	switch {
	case len(at) > 0:
		id := slices.MinFunc(at, func(a, b Row) int { return cmp.Compare(a.ID, b.ID) }).ID
		return &VerifyResult{FirstBreakAt: seq, Reason: fmt.Sprintf("row %s: hash differs from checkpoint at seq %d", id, seq)}
	case seq > highest:
		return &VerifyResult{FirstBreakAt: highest + 1, Reason: fmt.Sprintf(
			"node '%s': chain ends at seq %d before checkpoint at seq %d", cp.SourceNodeID, highest, seq)}
	case seq < lowest && newest:
		return &VerifyResult{FirstBreakAt: lowest, Reason: fmt.Sprintf(
			"node '%s': rows start at seq %d, after the newest checkpoint at seq %d", cp.SourceNodeID, lowest, seq)}
	case seq < lowest:
		return nil // purged by retention
	default:
		return &VerifyResult{FirstBreakAt: seq, Reason: fmt.Sprintf("node '%s': no row at checkpointed seq %d", cp.SourceNodeID, seq)}
	}
}
