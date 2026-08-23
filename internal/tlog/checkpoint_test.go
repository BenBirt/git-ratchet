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

package tlog

import (
	"strings"
	"testing"
)

func TestCheckpointRoundTrip(t *testing.T) {
	root := HashLeaf([]byte("root"))
	cp := NewCheckpoint("github.com/example/repo", 1234, root)

	got, gotRoot, err := ParseCheckpoint(string(cp.Marshal()))
	if err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	}
	if got.Origin != cp.Origin || got.Size != cp.Size {
		t.Errorf("round trip = %+v, want %+v", got, cp)
	}
	if gotRoot != root {
		t.Error("root hash did not survive the round trip")
	}
}

func TestCheckpointBodyFormat(t *testing.T) {
	cp := NewCheckpoint("github.com/example/repo", 42, HashLeaf([]byte("x")))
	lines := strings.Split(string(cp.Marshal()), "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("body should be three newline-terminated lines, got %q", cp.Marshal())
	}
	if lines[0] != "github.com/example/repo" || lines[1] != "42" {
		t.Errorf("origin/size lines = %q, %q", lines[0], lines[1])
	}
}

// TestParseCheckpointRejectsBadRootLength covers the check the library leaves
// to the caller: Unmarshal accepts any base64 hash, but a root hash of the
// wrong length is not a valid tree head.
func TestParseCheckpointRejectsBadRootLength(t *testing.T) {
	if _, _, err := ParseCheckpoint("example.com/log\n5\nAAAA\n"); err == nil {
		t.Error("expected a short root hash to be rejected")
	}
}

func TestParseCheckpointErrors(t *testing.T) {
	valid := string(NewCheckpoint("o", 1, HashLeaf(nil)).Marshal())
	rootLine := strings.SplitN(valid, "\n", 3)[2]

	for _, tc := range []struct{ name, body string }{
		{"too short", "example.com/log\n5\n"},
		{"empty origin", "\n5\n" + rootLine},
		{"non-numeric size", "example.com/log\nmany\n" + rootLine},
		{"negative size", "example.com/log\n-1\n" + rootLine},
		{"bad base64", "example.com/log\n5\nnot!base64\n"},
		{"empty", ""},
	} {
		if _, _, err := ParseCheckpoint(tc.body); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}

func TestRootFromBytes(t *testing.T) {
	root := HashLeaf([]byte("x"))
	got, err := RootFromBytes(root[:])
	if err != nil || got != root {
		t.Errorf("RootFromBytes round trip = %v, %v", got, err)
	}
	if _, err := RootFromBytes([]byte{1, 2, 3}); err == nil {
		t.Error("expected a short hash to be rejected")
	}
}
