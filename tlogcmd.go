// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	fpolicy "github.com/transparency-dev/formats/policy"
	whttp "github.com/transparency-dev/witness/client/http"
	"github.com/transparency-dev/witness/witness"

	"github.com/project-oak/git-ratchet/internal/gitlog"
	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// Checkpoint format modes. See docs/tlog-variant.md for how they differ.
const (
	// modeGitCheckpoint stores a signed note per ref, and witnesses enforce
	// Git ancestry when cosigning it.
	modeGitCheckpoint = "git-checkpoint"
	// modeTlog stores a Merkle transparency log in the repository, and
	// witnesses enforce only that the log grew by appending.
	modeTlog = "tlog"
)

// validateMode rejects anything that is not one of the two supported modes.
func validateMode(mode string) error {
	if mode != modeGitCheckpoint && mode != modeTlog {
		return fmt.Errorf("--mode must be %q or %q, got %q", modeGitCheckpoint, modeTlog, mode)
	}
	return nil
}

// checkpointTlog appends the ref's current object hash to the repository's
// transparency log, has the log's new head cosigned by the policy's witnesses,
// and commits both to the log ref.
func checkpointTlog(repoDir, ref, origin string, signer *note.Signer, pol *fpolicy.TLogPolicy) error {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return fmt.Errorf("opening log: %w", err)
	}

	objectHash, err := gitutil.ResolveRef(repoDir, ref)
	if err != nil {
		return fmt.Errorf("resolving ref: %w", err)
	}

	// The size the witnesses are expected to be holding is the size of the
	// last checkpoint this repository stored. If a witness disagrees it says
	// so, and the client regenerates its proof from the size the witness
	// actually holds.
	oldSize := uint64(0)
	if stored := l.StoredCheckpoint(); stored != "" {
		body, err := note.ExtractBody(stored)
		if err != nil {
			return fmt.Errorf("parsing stored checkpoint: %w", err)
		}
		prev, _, err := tlog.ParseCheckpoint(body)
		if err != nil {
			return fmt.Errorf("parsing stored checkpoint: %w", err)
		}
		oldSize = prev.Size
	}

	// Appending an entry identical to the ref's latest logged state would grow
	// the log without saying anything new, so re-checkpointing an unchanged
	// ref just refreshes the cosignatures on the current head. The view here
	// is over everything the log holds, which is what this checkpoint is about
	// to commit to.
	pending, err := l.Checkpointed(l.Size())
	if err != nil {
		return err
	}
	records, err := pending.RefRecords(ref)
	if err != nil {
		return err
	}
	appended := false
	if len(records) == 0 || records[len(records)-1].Object != objectHash {
		entry, err := gitlog.NewRefRecord(ref, objectHash)
		if err != nil {
			return err
		}
		l.Append(entry)
		appended = true
	}
	if l.Size() == 0 {
		return fmt.Errorf("refusing to checkpoint an empty log")
	}

	cp := tlog.NewCheckpoint(origin, l.Size(), l.Root())
	signed, err := note.SignTlogCheckpoint(string(cp.Marshal()), signer)
	if err != nil {
		return fmt.Errorf("signing checkpoint: %w", err)
	}

	cosigLines, err := collectTlogCosignatures(pol, l, oldSize, signed)
	if err != nil {
		return err
	}

	assembled := signed
	for _, line := range cosigLines {
		assembled = note.AppendSignature(assembled, line)
	}
	// The origin signed the checkpoint itself, so all it needs to know is
	// that enough witnesses cosigned it.
	if !pol.Satisfied([]byte(assembled)) {
		return fmt.Errorf("quorum %q not satisfied by %d cosignatures", pol.Quorum, len(cosigLines))
	}

	msg := fmt.Sprintf("ratchet: %s %s (log size %d)", ref, objectHash, l.Size())
	if !appended {
		msg = fmt.Sprintf("ratchet: refresh cosignatures at log size %d", l.Size())
	}
	if err := l.Save(assembled, msg); err != nil {
		return err
	}

	fmt.Printf("checkpoint stored at %s (log size %d, %d witness cosignatures)\n",
		gitlog.LogRef, l.Size(), len(cosigLines))
	return nil
}

// collectTlogCosignatures submits the signed checkpoint to every witness in
// the policy, in parallel, and returns the cosignature lines collected.
func collectTlogCosignatures(pol *fpolicy.TLogPolicy, l *gitlog.Log, oldSize uint64, signed string) ([]string, error) {
	type result struct {
		policyName string
		cosigLine  string
		err        error
	}
	witnesses := pol.Witnesses
	ch := make(chan result, len(witnesses))
	for _, w := range witnesses {
		go func(w fpolicy.Witness) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if w.URL == nil {
				ch <- result{w.Name, "", fmt.Errorf("witness %s declares no URL", w.Name)}
				return
			}
			if w.URL.Scheme != "http" && w.URL.Scheme != "https" {
				ch <- result{w.Name, "", fmt.Errorf("unsupported witness transport %q for tlog mode", w.URL.Scheme)}
				return
			}
			line, err := cosignWithWitness(ctx, w.URL, l, oldSize, signed)
			ch <- result{w.Name, line, err}
		}(w)
	}

	var cosigLines []string
	for range witnesses {
		r := <-ch
		if r.err != nil {
			// A witness that inspected the transition and refused it is
			// evidence the log did not grow by appending, which is never
			// skipped in favour of another witness's quorum. A witness that
			// could not be reached, or that has fallen behind us, is not.
			if errors.Is(r.err, witness.ErrInvalidProof) || errors.Is(r.err, witness.ErrRootMismatch) {
				return nil, fmt.Errorf("witness %s rejected checkpoint: %w", r.policyName, r.err)
			}
			fmt.Fprintf(os.Stderr, "warning: witness %s failed (skipped): %v\n", r.policyName, r.err)
			continue
		}
		cosigLines = append(cosigLines, r.cosigLine)
	}
	return cosigLines, nil
}

// checkpointedView opens the repository's log and returns the part of it that
// a checkpoint signed by the log and cosigned to the policy's quorum commits
// to. That prefix is everything verification is entitled to read.
func checkpointedView(repoDir string, pol *fpolicy.TLogPolicy) (*gitlog.View, error) {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return nil, fmt.Errorf("opening log: %w", err)
	}

	stored := l.StoredCheckpoint()
	if stored == "" {
		return nil, fmt.Errorf("no log checkpoint found (hint: git fetch origin %s:%s)", gitlog.LogRef, gitlog.LogRef)
	}

	// Verify covers both the log signature and the witness quorum, and only
	// accepts a checkpoint whose origin line matches the policy's log key.
	if _, err := pol.Verify([]byte(stored)); err != nil {
		return nil, fmt.Errorf("log checkpoint verification failed: %w", err)
	}

	body, err := note.ExtractBody(stored)
	if err != nil {
		return nil, fmt.Errorf("parsing log checkpoint: %w", err)
	}
	cp, cpRoot, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return nil, fmt.Errorf("malformed log checkpoint: %w", err)
	}

	v, err := l.Checkpointed(cp.Size)
	if err != nil {
		return nil, err
	}
	if v.Root() != cpRoot {
		return nil, fmt.Errorf("log entries do not reproduce the cosigned root hash")
	}
	return v, nil
}

// verifySingleRefTlog checks one ref against the verified log.
//
// Every ratchet property is established here, from entries held locally: a
// branch's logged states must each descend from the one before, and a tag must
// be logged exactly once.
//
// Entries of unrecognised types are skipped, which can leave the latest logged
// state behind the real ref. The final comparison rejects a ref ahead of the
// log, so that case fails rather than passing quietly.
func verifySingleRefTlog(repoDir, ref string, v *gitlog.View) error {
	kind, err := gitutil.ParseRefKind(ref)
	if err != nil {
		return err
	}

	entries, err := v.RefRecords(ref)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("no log entries for ref %q", ref)
	}

	switch kind {
	case gitutil.RefTag:
		// Tags are create-once: a second entry for the same tag is a move,
		// whatever object it names.
		if len(entries) > 1 {
			return fmt.Errorf("tag was logged %d times (first %s, last %s); tags must be logged exactly once",
				len(entries), entries[0].Object, entries[len(entries)-1].Object)
		}
	case gitutil.RefBranch:
		// Each logged state must descend from the one before it.
		for i := 1; i < len(entries); i++ {
			prev, curr := entries[i-1].Object, entries[i].Object
			ok, err := gitutil.IsAncestor(repoDir, prev, curr)
			if err != nil {
				return fmt.Errorf("cannot check ancestry from logged commit %s to %s "+
					"(the object may be missing from this clone, which is itself evidence "+
					"that logged history was discarded): %w", prev, curr, err)
			}
			if !ok {
				return fmt.Errorf("log entry %d for %s (%s) does not descend from entry %d (%s): history was rewritten",
					i, ref, curr, i-1, prev)
			}
		}
	}

	latest := entries[len(entries)-1]
	localHash, err := gitutil.ResolveRef(repoDir, ref)
	if err != nil {
		return fmt.Errorf("resolving ref: %w", err)
	}

	if kind == gitutil.RefTag {
		if localHash != latest.Object {
			return fmt.Errorf("tag does not match log (current: %s, logged: %s)", localHash, latest.Object)
		}
		return nil
	}

	ok, err := gitutil.IsAncestor(repoDir, localHash, latest.Object)
	if err != nil {
		return fmt.Errorf("checking ancestry: %w", err)
	}
	if !ok {
		return fmt.Errorf("local commit %s is ahead of the latest logged commit %s", localHash, latest.Object)
	}
	return nil
}

// cosignWithWitness performs one add-checkpoint exchange with a witness.
//
// A witness holding a different size answers with the size it does hold, and
// the proof has to be regenerated from there: a consistency proof is anchored
// to a specific size, unlike the commit chain git-checkpoint mode sends, which
// spans any gap. One retry is enough, because the size the witness reports is
// the size it will accept.
func cosignWithWitness(ctx context.Context, endpoint *url.URL, l *gitlog.Log, oldSize uint64, signed string) (string, error) {
	w := whttp.NewWitness(endpoint, http.DefaultClient)

	submit := func(from uint64) ([]byte, uint64, error) {
		proof, err := l.ConsistencyProofFrom(from)
		if err != nil {
			return nil, 0, fmt.Errorf("generating consistency proof from size %d: %w", from, err)
		}
		return w.Update(ctx, from, []byte(signed), rawHashes(proof))
	}

	cosig, actualSize, err := submit(oldSize)
	if errors.Is(err, witness.ErrCheckpointStale) && actualSize != oldSize {
		cosig, _, err = submit(actualSize)
		if err != nil {
			return "", fmt.Errorf("retry from witness size %d: %w", actualSize, err)
		}
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(cosig)), nil
}

// rawHashes converts proof hashes to the byte slices the witness client takes.
func rawHashes(hs []tlog.Hash) [][]byte {
	out := make([][]byte, 0, len(hs))
	for _, h := range hs {
		out = append(out, h[:])
	}
	return out
}
