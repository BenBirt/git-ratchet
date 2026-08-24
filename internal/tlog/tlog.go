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

// Package tlog builds the RFC 6962 Merkle tree behind git-ratchet's
// transparency-log mode: leaf and root hashes, consistency proofs for
// submission to a witness, and the tlog-checkpoint body committing to a tree.
//
// The tree comes from github.com/transparency-dev/merkle. This package adapts
// it in two ways. It works in fixed-size [Hash] values rather than []byte, so
// hashes compare and store naturally. And [nodeSource] resolves proof nodes
// from the leaves in memory, because the library reports which nodes a proof
// needs and leaves fetching them to the caller: it is built for logs whose
// nodes live in tiled storage, and a git-ratchet log is held whole.
//
// Proofs are verified by whoever receives them. Witnesses are not run here.
package tlog

import (
	"crypto/sha256"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// HashSize is the length of a node hash in bytes. The library's hasher is
// checked against it at start-up by the assertion below.
const HashSize = sha256.Size

// Hash is a Merkle tree node hash.
type Hash [HashSize]byte

// hasher is the RFC 6962 SHA-256 hasher: leaves are SHA-256(0x00 || data) and
// interior nodes are SHA-256(0x01 || left || right).
var hasher = rfc6962.DefaultHasher

// Guard against HashSize drifting from the configured hasher.
var _ = func() struct{} {
	if got := hasher.Size(); got != HashSize {
		panic(fmt.Sprintf("tlog: hasher emits %d-byte hashes, but HashSize is %d", got, HashSize))
	}
	return struct{}{}
}()

// rangeFactory builds compact ranges, the library's representation of a set of
// perfect subtrees, which is how tree roots are computed here.
var rangeFactory = compact.RangeFactory{Hash: hasher.HashChildren}

// Count converts a Go length to the uint64 this package counts leaves in.
//
// Tree sizes and leaf indices are uint64 throughout, which is what the C2SP
// formats and the merkle library both use, so a size crossing a wire boundary
// needs no conversion at all. This is the only conversion left, and it cannot
// fail: len never returns a negative value. The check is an assertion that no
// bare numeric conversion goes unexamined.
func Count(n int) uint64 {
	if n < 0 {
		panic(fmt.Sprintf("tlog: negative length %d", n))
	}
	return uint64(n)
}

// toHash converts a library hash to a fixed-size Hash. It panics if the length
// is wrong, which would mean the hasher was misconfigured rather than that any
// input was bad.
func toHash(b []byte) Hash {
	if len(b) != HashSize {
		panic(fmt.Sprintf("tlog: hash is %d bytes, want %d", len(b), HashSize))
	}
	var h Hash
	copy(h[:], b)
	return h
}

// raw converts a slice of Hash values to the library's representation.
func raw(hashes []Hash) [][]byte {
	out := make([][]byte, len(hashes))
	for i := range hashes {
		out[i] = append([]byte(nil), hashes[i][:]...)
	}
	return out
}

// wrap converts the library's representation back to Hash values.
func wrap(hashes [][]byte) []Hash {
	if len(hashes) == 0 {
		return nil
	}
	out := make([]Hash, len(hashes))
	for i := range hashes {
		out[i] = toHash(hashes[i])
	}
	return out
}

// HashLeaf returns the leaf hash SHA-256(0x00 || data).
func HashLeaf(data []byte) Hash {
	return toHash(hasher.HashLeaf(data))
}

// emptyRoot is the Merkle tree hash of an empty log: SHA-256 of the empty
// string, per RFC 6962 section 2.1.
func emptyRoot() Hash {
	return toHash(hasher.EmptyRoot())
}

// Root returns the Merkle tree hash of the given leaf hashes.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return emptyRoot()
	}
	r := rangeFactory.NewEmptyRange(0)
	for i := range leaves {
		// Append rejects only a leaf that does not extend the range. This
		// range starts empty at zero and is appended to in order, so a failure
		// here would be a bug in this loop rather than bad input.
		if err := r.Append(leaves[i][:], nil); err != nil {
			panic(fmt.Sprintf("tlog: appending leaf %d to an in-order range: %v", i, err))
		}
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		panic(fmt.Sprintf("tlog: computing root of %d leaves: %v", len(leaves), err))
	}
	return toHash(root)
}

// nodeSource resolves tree nodes for proof generation from an in-memory leaf
// list.
type nodeSource []Hash

// hash returns the hash of a perfect subtree node. Proof generation only ever
// asks for nodes whose subtree lies wholly within the tree, so the leaf range
// is always complete.
func (s nodeSource) hash(id compact.NodeID) (Hash, error) {
	begin, end := id.Index<<id.Level, (id.Index+1)<<id.Level
	if end > Count(len(s)) {
		return Hash{}, fmt.Errorf("node (level %d, index %d) is outside a tree of %d leaves", id.Level, id.Index, len(s))
	}
	return Root(s[begin:end]), nil
}

// fetch resolves every node a proof needs and collapses the ephemeral node, if
// there is one, into the proof hashes.
func (s nodeSource) fetch(nodes proof.Nodes) ([]Hash, error) {
	hashes := make([][]byte, 0, len(nodes.IDs))
	for _, id := range nodes.IDs {
		h, err := s.hash(id)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	rehashed, err := nodes.Rehash(hashes, hasher.HashChildren)
	if err != nil {
		return nil, fmt.Errorf("assembling proof: %w", err)
	}
	return wrap(rehashed), nil
}

// ConsistencyProof returns the proof that a tree of size m is a prefix of a
// tree of the given leaves.
//
// A proof from size 0 is empty: every tree is consistent with the empty tree.
// So is a proof to the same size.
func ConsistencyProof(leaves []Hash, m uint64) ([]Hash, error) {
	n := Count(len(leaves))
	if m > n {
		return nil, fmt.Errorf("old size %d out of range for tree of size %d", m, n)
	}
	if m == 0 || m == n {
		return nil, nil
	}
	nodes, err := proof.Consistency(m, n)
	if err != nil {
		return nil, err
	}
	return nodeSource(leaves).fetch(nodes)
}
