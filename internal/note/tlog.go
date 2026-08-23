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

package note

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"

	fnote "github.com/transparency-dev/formats/note"
	sumdbnote "golang.org/x/mod/sumdb/note"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

// Signatures over C2SP tlog-checkpoint notes are produced and verified by
// github.com/transparency-dev/formats, not by the constructions in note.go.
//
// The two disagree about ML-DSA-44, and formats is right. C2SP signed-note
// assigns 0x06 to "timestamped ML-DSA-44 (sub)tree cosignatures" and assigns
// nothing to a plain ML-DSA-44 signature over a note's text, so an ML-DSA-44
// signature is always the cosigned_message construction — a binary structure
// committing to the cosigner's name, a timestamp, the log origin, a leaf range
// and a Merkle root. A log signing its own checkpoint signs exactly the message
// a witness would, over the range [0, size). That is well defined only over a
// tlog-checkpoint, which is why git-checkpoint mode is Ed25519-only.
//
// For Ed25519 the two agree, and the wire encodings match throughout: the
// algorithm bytes are the same (0x01 origin, 0x04 cosigner, 0x06 ML-DSA-44),
// the key hash is SHA-256(name || "\n" || algorithm || public key) truncated to
// four bytes in both, and a signature is keyHash(4) || signature, with an
// 8-byte big-endian timestamp ahead of the signature for the cosignature types.
// Verifier keys therefore need no conversion at all.

// skeyForFormats renders a signer's private key in the "PRIVATE+KEY+..."
// encoding the formats package parses.
//
// TODO: migrate the on-disk key format to this encoding so keys can be read
// straight into a formats signer, and delete this shim. The formats encoding
// carries the algorithm byte alongside the seed, which is what lets a single
// parser accept any algorithm; ours splits that across the vkey line and the
// seed line, and needs the caller to say which role the key plays.
func skeyForFormats(s *Signer) (string, error) {
	switch s.SigType {
	case Ed25519Origin, Ed25519Cosigner, MLDSA44:
	default:
		return "", fmt.Errorf("unsupported signature type: 0x%02x", s.SigType)
	}
	if len(s.seed) == 0 {
		// A KMS-backed signer holds no key material locally, so it cannot be
		// rendered as a private key at all. Ed25519 keys avoid this path
		// entirely; see SignTlogCheckpoint.
		return "", fmt.Errorf("signer %q has no local key material", s.Name)
	}
	key := append([]byte{byte(s.SigType)}, s.seed...)
	return fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s",
		s.Name, binary.BigEndian.Uint32(s.hash[:]), base64.StdEncoding.EncodeToString(key)), nil
}

// tlogSigner returns a formats signer for the given key. It signs a
// tlog-checkpoint note body according to the key's algorithm: a plain note
// signature for 0x01, and the timestamped cosigned_message for 0x04 and 0x06.
func tlogSigner(s *Signer) (sumdbnote.Signer, error) {
	skey, err := skeyForFormats(s)
	if err != nil {
		return nil, err
	}
	return fnote.NewSigner(skey)
}

// SignTlogCheckpoint signs a tlog-checkpoint body as the log, returning the
// signed note. The signer must have RoleOrigin.
func SignTlogCheckpoint(body string, signer *Signer) (string, error) {
	if signer.Role != RoleOrigin {
		return "", fmt.Errorf("SignTlogCheckpoint requires an origin key, got cosigner")
	}
	// The ML-DSA-44 signer parses the body as a checkpoint itself, but the
	// Ed25519 one does not, so reject a non-checkpoint body here for both.
	if _, _, err := tlog.ParseCheckpoint(body); err != nil {
		return "", fmt.Errorf("not a tlog checkpoint: %w", err)
	}

	switch signer.SigType {
	case Ed25519Origin:
		// 0x01 is a plain note signature over the body, which is what Sign
		// already produces, byte for byte. Going through the formats signer
		// instead would rule out KMS-backed keys, which hold no local seed
		// for the shim to render.
		return Sign(body, signer)

	case MLDSA44:
		s, err := tlogSigner(signer)
		if err != nil {
			return "", err
		}
		signed, err := sumdbnote.Sign(&sumdbnote.Note{Text: body}, s)
		if err != nil {
			return "", fmt.Errorf("signing checkpoint: %w", err)
		}
		return string(signed), nil

	default:
		return "", fmt.Errorf("unsupported log signature type: 0x%02x", signer.SigType)
	}
}

// Verifying a signed tlog-checkpoint has no wrapper here: log.ParseCheckpoint
// in transparency-dev/formats opens the note, confirms the log signed it, and
// checks the origin line against the log's key name, which is every check a
// caller needs and one more than a bare note.Open gives.

// CosignTlogCheckpoint creates a cosignature line for a signed tlog-checkpoint.
// The signer must have RoleCosigner.
//
// Wire format, as in Cosign: keyHash(4) || timestamp(8) || signature.
func CosignTlogCheckpoint(signedNote string, signer *Signer) (string, error) {
	if signer.Role != RoleCosigner {
		return "", fmt.Errorf("CosignTlogCheckpoint requires a cosigner key, got origin")
	}

	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}
	// The ML-DSA-44 signer parses the body as a checkpoint itself, but the
	// Ed25519 one does not, so reject a non-checkpoint body here for both.
	if _, _, err := tlog.ParseCheckpoint(body); err != nil {
		return "", fmt.Errorf("not a tlog checkpoint: %w", err)
	}

	if signer.SigType == Ed25519Cosigner {
		// As in SignTlogCheckpoint: the 0x04 construction is the one Cosign
		// already produces, and taking it keeps KMS-backed keys working.
		return Cosign(signedNote, signer)
	}
	if signer.SigType != MLDSA44 {
		return "", fmt.Errorf("unsupported cosigner signature type: 0x%02x", signer.SigType)
	}

	cosigner, err := tlogSigner(signer)
	if err != nil {
		return "", err
	}
	// The returned signature is timestamp || signature; the key hash is
	// prepended here, as the signed-note wire format requires.
	sig, err := cosigner.Sign([]byte(body))
	if err != nil {
		return "", fmt.Errorf("cosigning checkpoint: %w", err)
	}

	raw := append(append([]byte{}, signer.hash[:]...), sig...)
	return SigPrefix + signer.Name + " " + base64.StdEncoding.EncodeToString(raw), nil
}

// ed25519CosignMessage returns the message an Ed25519 cosignature covers, per
// the tlog-cosignature specification. It is generic over the note body, and is
// used by the git-checkpoint cosignatures in note.go; tlog-checkpoint
// cosignatures get the equivalent from the formats package.
func ed25519CosignMessage(timestamp uint64, body string) string {
	return cosignatureV1Prefix + "\n" +
		"time " + strconv.FormatUint(timestamp, 10) + "\n" +
		body
}
