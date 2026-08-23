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
	"fmt"

	"github.com/transparency-dev/formats/log"
)

// The C2SP tlog-checkpoint body comes from github.com/transparency-dev/formats:
// [log.Checkpoint] carries the origin, tree size and root hash, and marshals
// them as the specification requires.
//
// The helper here covers the one thing that type leaves to the caller. Its
// Hash field is a byte slice of any length, whereas everything in this package
// works in fixed-size [Hash] values. Its Size field needs nothing: sizes are
// uint64 here as they are on the wire.

// ParseCheckpoint parses a tlog-checkpoint body and returns it with the root
// hash checked and converted to a [Hash].
//
// Any lines after the root hash are extension lines, which are preserved in
// the body the signature covers but are not interpreted here.
func ParseCheckpoint(body string) (cp log.Checkpoint, root Hash, err error) {
	if _, err := cp.Unmarshal([]byte(body)); err != nil {
		return log.Checkpoint{}, Hash{}, err
	}
	root, err = RootFromBytes(cp.Hash)
	if err != nil {
		return log.Checkpoint{}, Hash{}, fmt.Errorf("invalid checkpoint: %w", err)
	}
	return cp, root, nil
}

// NewCheckpoint builds a checkpoint for a tree of the given size and root.
func NewCheckpoint(origin string, size uint64, root Hash) log.Checkpoint {
	return log.Checkpoint{Origin: origin, Size: size, Hash: root[:]}
}

// RootFromBytes converts a root hash to a [Hash], rejecting the wrong length.
func RootFromBytes(b []byte) (Hash, error) {
	if len(b) != HashSize {
		return Hash{}, fmt.Errorf("root hash is %d bytes, want %d", len(b), HashSize)
	}
	return toHash(b), nil
}
