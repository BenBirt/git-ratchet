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
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/tlog"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

// tlogTestServer builds a witness in tlog mode trusting a single origin.
func tlogTestServer(t *testing.T) (*Server, *note.Signer) {
	t.Helper()
	logKey, err := note.GenerateKey("example.com/log", note.Ed25519Origin, note.RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	wit, err := note.GenerateKey("example.com/w1", note.Ed25519Cosigner, note.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	origins, err := parseOrigins([]string{logKey.VKey()})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		witnessKey:     wit,
		trustedOrigins: origins,
		mode:           modeTlog,
		commits:        map[string]string{},
		trees:          map[string]treeState{},
	}, logKey
}

// submit signs a checkpoint body as the log and runs it through the handler.
//
// It signs with note.Sign rather than note.SignTlogCheckpoint because the
// latter parses the body first and so refuses a checkpoint this witness must
// still be able to receive. A foreign log is under no such restraint, and the
// witness has to hold its own line.
func submit(t *testing.T, s *Server, logKey *note.Signer, oldSize, body string) *httptest.ResponseRecorder {
	t.Helper()
	signed, err := note.Sign(body, logKey)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleAddCheckpointTlog(w, httptest.NewRequest(http.MethodPost, "/add-checkpoint",
		strings.NewReader("old "+oldSize+"\n\n"+signed)))
	return w
}

// checkpointBody renders a tlog-checkpoint with an arbitrary size, including
// sizes no real log could reach.
func checkpointBody(size uint64) string {
	root := tlog.HashLeaf([]byte("root"))
	return fmt.Sprintf("example.com/log\n%d\n%s\n", size,
		base64.StdEncoding.EncodeToString(root[:]))
}

// TestTlogWitnessLargeSizeRoundTrips is a regression test for a tree size that
// overflowed the int the witness once stored.
//
// A checkpoint's size is a uint64 on the wire, and 2^63 is a legal value. When
// the witness narrowed it to an int, any size at or above 2^63 became
// negative, and it persisted that: every later submission was refused against
// a stored size that ParseTlogRequest rejects as malformed, so no client could
// ever satisfy the witness for that origin again.
//
// The witness still holds the origin to the size it signed — that is the
// ratchet, and it cannot see entries to know the size is absurd. What it must
// not do is store a size that cannot be expressed back to a client.
func TestTlogWitnessLargeSizeRoundTrips(t *testing.T) {
	s, logKey := tlogTestServer(t)
	const huge = uint64(math.MaxUint64)

	if w := submit(t, s, logKey, "0", checkpointBody(huge)); w.Code != http.StatusOK {
		t.Fatalf("first submission: status %d, body %q", w.Code, w.Body.String())
	}

	stored := s.trees["example.com/log"]
	if stored.Size != huge {
		t.Fatalf("stored size = %d, want %d", stored.Size, huge)
	}

	// The conflict a stale client gets must name a size it can send back.
	w := submit(t, s, logKey, "1", checkpointBody(huge))
	if w.Code != http.StatusConflict {
		t.Fatalf("stale submission: status %d, body %q", w.Code, w.Body.String())
	}
	first, _, _ := strings.Cut(w.Body.String(), "\n")
	req, err := iwitness.ParseTlogRequest(first + "\n\n" + "note")
	if err != nil {
		t.Fatalf("witness reported a size no client can resubmit: %q: %v", first, err)
	}
	if req.OldSize != huge {
		t.Errorf("reported size = %d, want %d", req.OldSize, huge)
	}
}
