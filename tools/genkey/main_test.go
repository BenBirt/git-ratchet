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

package main_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	flog "github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"

	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// verifyTlogCheckpoint checks that a signed tlog-checkpoint carries a valid
// signature from the key in vkey, using the same call the rest of the
// codebase does.
func verifyTlogCheckpoint(signedNote, origin, vkey string) error {
	v, err := fnote.NewVerifier(vkey)
	if err != nil {
		return err
	}
	_, _, _, err = flog.ParseCheckpoint([]byte(signedNote), origin, v)
	return err
}

// tlogCheckpointBody is a C2SP tlog-checkpoint body. ML-DSA-44 keys sign and
// cosign only these: 0x06 denotes the cosigned_message construction, which
// commits to a log origin, a leaf range and a Merkle root.
func tlogCheckpointBody(origin string) string {
	return string(tlog.NewCheckpoint(origin, 7, tlog.HashLeaf([]byte("root"))).Marshal())
}

func mustFindBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GENKEY_BIN"); p != "" {
		return p
	}
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "tools", "genkey", "genkey_", "genkey"),
				filepath.Join(srcDir, ws, "tools", "genkey", "genkey"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("genkey binary not found; run with: bazel test //tools/genkey:genkey_test")
	return ""
}

// runGenKey runs genkey and returns its stdout, which is the private key, and
// its stderr, which carries the vkey for the operator to copy into a policy.
func runGenKey(t *testing.T, args ...string) (stdout []byte, stderr string) {
	t.Helper()

	var errBuf bytes.Buffer
	cmd := exec.Command(mustFindBinary(t), args...)
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("genkey failed: %v (stderr: %s)", err, errBuf.String())
	}
	return out, errBuf.String()
}

// checkSKey asserts that genkey wrote a single private key line in the C2SP
// signed-note encoding, and returns the algorithm byte it carries.
func checkSKey(t *testing.T, out []byte, name string) note.SigType {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line in key output, got %d", len(lines))
	}

	rest, ok := strings.CutPrefix(lines[0], "PRIVATE+KEY+")
	if !ok {
		t.Fatalf("key output is not a private key: %s", lines[0])
	}
	// Split from the left and take everything after the key hash as the key
	// material: base64's alphabet includes "+", so only the leading fields can
	// be delimited.
	parts := strings.SplitN(rest, "+", 3)
	if len(parts) != 3 {
		t.Fatalf("key output malformed: %s", lines[0])
	}
	if parts[0] != name {
		t.Fatalf("expected key name %s, got %s", name, parts[0])
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(parts[1]) {
		t.Fatalf("key hash format invalid: %s", parts[1])
	}

	key, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding private key: %v", err)
	}
	// 1 algorithm byte and a 32-byte seed, for both Ed25519 and ML-DSA-44.
	if len(key) != 33 {
		t.Fatalf("expected 33 bytes of key material, got %d", len(key))
	}
	return note.SigType(key[0])
}

// checkVKey asserts that the vkey genkey printed to stderr is the one the
// private key produces, and that it carries a public key of the given size.
func checkVKey(t *testing.T, stderr, vkey, name string, sigType note.SigType, pubKeySize int) {
	t.Helper()

	if !regexp.MustCompile(`^` + regexp.QuoteMeta(name) + `\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
		t.Fatalf("vkey format invalid: %s", vkey)
	}
	if !strings.Contains(stderr, vkey) {
		t.Fatalf("expected vkey %s on stderr, got: %s", vkey, stderr)
	}

	pubName, pubSigType, _, err := note.ParseVKey(vkey)
	if err != nil {
		t.Fatalf("note.ParseVKey: %v", err)
	}
	if pubName != name {
		t.Fatalf("expected pubName %s, got %s", name, pubName)
	}
	if pubSigType != sigType {
		t.Fatalf("expected type byte 0x%02x, got 0x%02x", byte(sigType), byte(pubSigType))
	}

	data, err := base64.StdEncoding.DecodeString(strings.SplitN(vkey, "+", 3)[2])
	if err != nil {
		t.Fatalf("decoding vkey data: %v", err)
	}
	// 1 algorithm byte and the public key itself.
	if len(data) != 1+pubKeySize {
		t.Fatalf("expected %d bytes of vkey data, got %d", 1+pubKeySize, len(data))
	}
}

func TestGenKey_Origin_Ed25519(t *testing.T) {
	out, stderr := runGenKey(t, "--role", "origin", "--algo", "ed25519", "--name", "test-origin")

	if sigType := checkSKey(t, out, "test-origin"); sigType != note.Ed25519Origin {
		t.Fatalf("expected type byte 0x%02x, got 0x%02x", byte(note.Ed25519Origin), byte(sigType))
	}

	readSigner, err := note.ReadKeyData(out, note.RoleOrigin)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	vkey := readSigner.VKey()
	checkVKey(t, stderr, vkey, "test-origin", note.Ed25519Origin, 32)

	testBody := "test-origin refs/heads/main\n0123456789abcdef0123456789abcdef01234567\n"
	signedNote, err := note.Sign(testBody, readSigner)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}

	body, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		t.Fatalf("note.ParseSignedNote: %v", err)
	}
	if len(sigLines) != 1 {
		t.Fatalf("expected 1 signature line, got %d", len(sigLines))
	}

	_, sigType, pubKey, err := note.ParseVKey(vkey)
	if err != nil {
		t.Fatalf("note.ParseVKey: %v", err)
	}
	if err := note.VerifySignature(body, sigLines[0], pubKey, sigType); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestGenKey_Origin_MLDSA(t *testing.T) {
	out, stderr := runGenKey(t, "--role", "origin", "--algo", "mldsa44", "--name", "test-origin-pq")

	if sigType := checkSKey(t, out, "test-origin-pq"); sigType != note.MLDSA44 {
		t.Fatalf("expected type byte 0x%02x, got 0x%02x", byte(note.MLDSA44), byte(sigType))
	}

	readSigner, err := note.ReadKeyData(out, note.RoleOrigin)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	vkey := readSigner.VKey()
	checkVKey(t, stderr, vkey, "test-origin-pq", note.MLDSA44, 1312)

	signedNote, err := note.SignTlogCheckpoint(tlogCheckpointBody("test-origin-pq"), readSigner)
	if err != nil {
		t.Fatalf("note.SignTlogCheckpoint: %v", err)
	}

	_, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		t.Fatalf("note.ParseSignedNote: %v", err)
	}
	if len(sigLines) != 1 {
		t.Fatalf("expected 1 signature line, got %d", len(sigLines))
	}

	if err := verifyTlogCheckpoint(signedNote, "test-origin-pq", vkey); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestGenKey_Witness_Ed25519(t *testing.T) {
	out, stderr := runGenKey(t, "--role", "witness", "--algo", "ed25519", "--name", "test-witness")

	if sigType := checkSKey(t, out, "test-witness"); sigType != note.Ed25519Cosigner {
		t.Fatalf("expected type byte 0x%02x, got 0x%02x", byte(note.Ed25519Cosigner), byte(sigType))
	}

	readSigner, err := note.ReadKeyData(out, note.RoleCosigner)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	vkey := readSigner.VKey()
	checkVKey(t, stderr, vkey, "test-witness", note.Ed25519Cosigner, 32)

	originSigner, err := note.GenerateKey("test-origin", note.Ed25519Origin, note.RoleOrigin)
	if err != nil {
		t.Fatalf("GenerateKey origin: %v", err)
	}

	testBody := "test-origin refs/heads/main\n0123456789abcdef0123456789abcdef01234567\n"
	signedNote, err := note.Sign(testBody, originSigner)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}

	cosigLine, err := note.Cosign(signedNote, readSigner)
	if err != nil {
		t.Fatalf("note.Cosign: %v", err)
	}

	body, err := note.ExtractBody(signedNote)
	if err != nil {
		t.Fatalf("note.ExtractBody: %v", err)
	}

	_, sigType, pubKey, err := note.ParseVKey(vkey)
	if err != nil {
		t.Fatalf("note.ParseVKey: %v", err)
	}
	if err := note.VerifyCosignature(body, cosigLine, pubKey, sigType); err != nil {
		t.Fatalf("cosignature verification failed: %v", err)
	}
}

func TestGenKey_Witness_MLDSA(t *testing.T) {
	out, stderr := runGenKey(t, "--role", "witness", "--algo", "mldsa44", "--name", "test-witness-pq")

	if sigType := checkSKey(t, out, "test-witness-pq"); sigType != note.MLDSA44 {
		t.Fatalf("expected type byte 0x%02x, got 0x%02x", byte(note.MLDSA44), byte(sigType))
	}

	readSigner, err := note.ReadKeyData(out, note.RoleCosigner)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	vkey := readSigner.VKey()
	checkVKey(t, stderr, vkey, "test-witness-pq", note.MLDSA44, 1312)

	originSigner, err := note.GenerateKey("test-origin", note.Ed25519Origin, note.RoleOrigin)
	if err != nil {
		t.Fatalf("GenerateKey origin: %v", err)
	}

	signedNote, err := note.SignTlogCheckpoint(tlogCheckpointBody("test-origin"), originSigner)
	if err != nil {
		t.Fatalf("note.SignTlogCheckpoint: %v", err)
	}

	cosigLine, err := note.CosignTlogCheckpoint(signedNote, readSigner)
	if err != nil {
		t.Fatalf("note.CosignTlogCheckpoint: %v", err)
	}

	if err := verifyTlogCheckpoint(note.AppendSignature(signedNote, cosigLine), "test-origin", vkey); err != nil {
		t.Fatalf("cosignature verification failed: %v", err)
	}
}

func TestGenKey_InvalidFlags(t *testing.T) {
	binary := mustFindBinary(t)

	// Invalid role
	cmdRole := exec.Command(binary, "--role", "invalid")
	if err := cmdRole.Run(); err == nil {
		t.Errorf("expected error for invalid role, got success")
	}

	// Invalid algo
	cmdAlgo := exec.Command(binary, "--algo", "invalid")
	if err := cmdAlgo.Run(); err == nil {
		t.Errorf("expected error for invalid algo, got success")
	}
}
