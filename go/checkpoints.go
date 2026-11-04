package fasten

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
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
// nil means http.DefaultClient; the context bounds the request.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("checkpoint sink %s: HTTP %d", s.URL, resp.StatusCode)
	}
	return nil
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

// LoadCheckpoints reads back a file written by FileCheckpointSink. Blank
// lines are skipped.
func LoadCheckpoints(path string) ([]Checkpoint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Checkpoint
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var raw struct {
			SourceNodeID *string `json:"source_node_id"`
			MonotonicSeq *int64  `json:"monotonic_seq"`
			Hash         *string `json:"hash"`
			AnchoredAt   *string `json:"anchored_at"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			return nil, fmt.Errorf("%s: not a checkpoint: %w", path, err)
		}
		if raw.SourceNodeID == nil || raw.MonotonicSeq == nil || raw.Hash == nil || raw.AnchoredAt == nil {
			return nil, fmt.Errorf("%s: not a checkpoint: %s", path, line)
		}
		out = append(out, Checkpoint{SourceNodeID: *raw.SourceNodeID, MonotonicSeq: *raw.MonotonicSeq, Hash: *raw.Hash, AnchoredAt: *raw.AnchoredAt})
	}
	return out, sc.Err()
}

// checkpointBreak checks rows, one copy per id, against checkpoints and
// returns the lowest-seq break, or nil. Checkpoints are taken by node, then
// seq, as in Python, so both report the same break.
func checkpointBreak(rows []Row, checkpoints []Checkpoint) *VerifyResult {
	if len(checkpoints) == 0 {
		return nil
	}
	byNode := map[string][]Row{}
	for _, row := range rows {
		byNode[row.SourceNodeID] = append(byNode[row.SourceNodeID], row)
	}
	sorted := slices.Clone(checkpoints)
	slices.SortStableFunc(sorted, func(a, b Checkpoint) int {
		return cmp.Or(cmp.Compare(a.SourceNodeID, b.SourceNodeID), cmp.Compare(a.MonotonicSeq, b.MonotonicSeq))
	})
	var first *VerifyResult
	for _, cp := range sorted {
		nodeRows := byNode[cp.SourceNodeID]
		if len(nodeRows) == 0 {
			continue
		}
		if found := checkpointMismatch(nodeRows, cp); found != nil && (first == nil || found.FirstBreakAt < first.FirstBreakAt) {
			first = found
		}
	}
	return first
}

// checkpointMismatch checks one node's rows against a checkpoint of that
// node; nil if they agree or the checkpoint is older than the oldest row.
func checkpointMismatch(rows []Row, cp Checkpoint) *VerifyResult {
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
	case seq < lowest:
		return nil // purged by retention
	default:
		return &VerifyResult{FirstBreakAt: seq, Reason: fmt.Sprintf("node '%s': no row at checkpointed seq %d", cp.SourceNodeID, seq)}
	}
}
