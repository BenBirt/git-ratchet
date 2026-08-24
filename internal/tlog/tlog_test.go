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
	"encoding/hex"
	"fmt"
	"testing"

	mproof "github.com/transparency-dev/merkle/proof"
)

// leaves builds n distinct leaf hashes.
func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = HashLeaf([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return out
}

// TestEmptyRoot pins the RFC 6962 empty tree hash: SHA-256 of the empty string.
func TestEmptyRoot(t *testing.T) {
	r := Root(nil)
	got := hex.EncodeToString(r[:])
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("Root(nil) = %s, want %s", got, want)
	}
}

// TestHashLeafEmpty pins the RFC 6962 hash of an empty leaf: SHA-256(0x00).
func TestHashLeafEmpty(t *testing.T) {
	h := HashLeaf(nil)
	got := hex.EncodeToString(h[:])
	want := "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
	if got != want {
		t.Errorf("HashLeaf(nil) = %s, want %s", got, want)
	}
}

// TestRootSingleLeaf checks that a one-leaf tree's root is the leaf itself.
func TestRootSingleLeaf(t *testing.T) {
	l := leaves(1)
	if Root(l) != l[0] {
		t.Error("root of a single-leaf tree should be the leaf hash")
	}
}

// TestConsistencyProofRoundTrip generates and verifies a consistency proof for
// every pair of sizes up to 64. m starts at 1: a proof from the empty tree has
// nothing to prove, and is covered by TestConsistencyProofFromEmpty.
func TestConsistencyProofRoundTrip(t *testing.T) {
	for n := uint64(1); n <= 64; n++ {
		l := leaves(int(n))
		newRoot := Root(l)
		for m := uint64(1); m <= n; m++ {
			oldRoot := Root(l[:m])
			proof, err := ConsistencyProof(l, m)
			if err != nil {
				t.Fatalf("n=%d m=%d: ConsistencyProof: %v", n, m, err)
			}
			if err := verifyConsistency(oldRoot, newRoot, proof, m, n); err != nil {
				t.Errorf("n=%d m=%d: VerifyConsistency: %v", n, m, err)
			}
		}
	}
}

// TestConsistencyProofRejectsForkedTree is the property the witness relies on:
// a tree that replaced an existing leaf rather than appending to it must not
// produce a valid consistency proof.
func TestConsistencyProofRejectsForkedTree(t *testing.T) {
	const m = 7
	original := leaves(12)
	oldRoot := Root(original[:m])

	// Fork the log: rewrite leaf 3, which the old tree already committed to.
	forked := make([]Hash, len(original))
	copy(forked, original)
	forked[3] = HashLeaf([]byte("rewritten"))

	proof, err := ConsistencyProof(forked, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyConsistency(oldRoot, Root(forked), proof, m, Count(len(forked))); err == nil {
		t.Error("expected a forked log to fail consistency verification")
	}
}

// TestConsistencyProofTamperedFails checks that flipping a bit in any proof
// hash is detected.
func TestConsistencyProofTamperedFails(t *testing.T) {
	const m, n = 5, 17
	l := leaves(n)
	oldRoot, newRoot := Root(l[:m]), Root(l)
	proof, err := ConsistencyProof(l, m)
	if err != nil {
		t.Fatal(err)
	}
	for j := range proof {
		tampered := make([]Hash, len(proof))
		copy(tampered, proof)
		tampered[j][0] ^= 0x01
		if err := verifyConsistency(oldRoot, newRoot, tampered, m, n); err == nil {
			t.Errorf("expected verification to fail with hash %d tampered", j)
		}
	}
}

// TestConsistencyProofEqualSize checks the m == n case: no proof, equal roots.
func TestConsistencyProofEqualSize(t *testing.T) {
	l := leaves(9)
	root := Root(l)
	if err := verifyConsistency(root, root, nil, 9, 9); err != nil {
		t.Errorf("equal roots at equal size should verify: %v", err)
	}
	if err := verifyConsistency(root, Root(leaves(8)), nil, 9, 9); err == nil {
		t.Error("differing roots at equal size should not verify")
	}
	if err := verifyConsistency(root, root, []Hash{root}, 9, 9); err == nil {
		t.Error("a non-empty proof at equal size should not verify")
	}
}

// TestConsistencyProofFromEmpty checks that growing from the empty tree needs
// no proof. Every tree extends the empty tree, so there is nothing to prove and
// nothing to verify; tlog-witness says as much, requiring the proof to be empty
// when the old size is zero.
func TestConsistencyProofFromEmpty(t *testing.T) {
	proof, err := ConsistencyProof(leaves(6), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Errorf("proof from size 0 should be empty, got %d hashes", len(proof))
	}
}

// TestConsistencyProofShrinkingRejected checks that a log cannot shrink.
func TestConsistencyProofShrinkingRejected(t *testing.T) {
	l := leaves(10)
	if err := verifyConsistency(Root(l), Root(l[:4]), nil, 10, 4); err == nil {
		t.Error("expected a shrinking tree to be rejected")
	}
}

// TestConsistencyProofOutOfRange checks size bounds on generation.
func TestConsistencyProofOutOfRange(t *testing.T) {
	l := leaves(4)
	if _, err := ConsistencyProof(l, 5); err == nil {
		t.Error("expected an error when the old size exceeds the tree")
	}
}

// TestConsistencyProofEmptyRejected checks that a missing proof cannot stand in
// for a real one when the tree has genuinely grown.
func TestConsistencyProofEmptyRejected(t *testing.T) {
	l := leaves(9)
	if err := verifyConsistency(Root(l[:5]), Root(l), nil, 5, 9); err == nil {
		t.Error("expected an empty proof to be rejected for a grown tree")
	}
}

// TestCountRejectsNegative pins the assertion in Count. A negative length
// cannot arise from len, so this is the only way to reach the panic; keeping
// it covered means the check is real rather than decorative.
func TestCountRejectsNegative(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected Count to panic on a negative length")
		}
	}()
	Count(-1)
}

// verifyConsistency checks a proof with the merkle library's own verifier, so
// these tests exercise the proof generation in this package rather than a
// wrapper of ours around the same library.
func verifyConsistency(oldRoot, newRoot Hash, p []Hash, m, n uint64) error {
	return mproof.VerifyConsistency(hasher, m, n, raw(p), oldRoot[:], newRoot[:])
}
