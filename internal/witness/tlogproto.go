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

package witness

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

// This file implements the add-checkpoint wire format of the C2SP tlog-witness
// protocol. The request carries an old tree size, a consistency proof and the
// signed checkpoint; it carries no Git objects.
//
// HTTP witnesses are reached through transparency-dev/witness, which formats
// and parses this itself. What needs it here is the decomposed workflow, where
// the same body travels as a file rather than as a POST: checkpoint-request
// writes one, and the GitHub Issue witness reads one.

// TlogRequest is a parsed add-checkpoint request.
type TlogRequest struct {
	// OldSize is the tree size the client believes the witness last signed.
	OldSize uint64
	// Proof is the consistency proof from OldSize to the checkpoint's size.
	Proof []tlog.Hash
	// Note is the raw signed tlog-checkpoint.
	Note string
}

// FormatTlogRequest renders an add-checkpoint request body:
//
//	old <size>\n
//	<base64 consistency proof hash>\n   (zero or more)
//	\n
//	<signed checkpoint note>
func FormatTlogRequest(oldSize uint64, proof []tlog.Hash, signedNote string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "old %d\n", oldSize)
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(signedNote)
	return b.String()
}

// ParseTlogRequest parses an add-checkpoint request body.
func ParseTlogRequest(body string) (TlogRequest, error) {
	var req TlogRequest

	lines := strings.Split(body, "\n")
	if len(lines) == 0 {
		return req, fmt.Errorf("malformed request: empty body")
	}

	sizeStr, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return req, fmt.Errorf("malformed request: first line must be \"old <size>\"")
	}
	oldSize, err := strconv.ParseUint(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		// ParseUint rejects a negative or oversized value as a parse error,
		// which is why nothing downstream has to range-check the size.
		return req, fmt.Errorf("malformed request: invalid old size %q", sizeStr)
	}
	req.OldSize = oldSize

	// Consistency proof hashes run until the blank line separator.
	i := 1
	for ; i < len(lines); i++ {
		if lines[i] == "" {
			break
		}
		raw, err := base64.StdEncoding.DecodeString(lines[i])
		if err != nil {
			return req, fmt.Errorf("malformed request: invalid base64 in consistency proof")
		}
		if len(raw) != tlog.HashSize {
			return req, fmt.Errorf("malformed request: consistency proof hash is %d bytes, want %d", len(raw), tlog.HashSize)
		}
		var h tlog.Hash
		copy(h[:], raw)
		req.Proof = append(req.Proof, h)
	}
	if i >= len(lines) {
		return req, fmt.Errorf("malformed request: missing empty line separator")
	}

	req.Note = strings.Join(lines[i+1:], "\n")
	if strings.TrimSpace(req.Note) == "" {
		return req, fmt.Errorf("malformed request: empty signed note")
	}
	return req, nil
}
