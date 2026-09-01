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

// Package note KMS support.
//
// This file implements a GCP Cloud KMS-backed crypto.Signer. The key material
// stays in KMS: what is held here is the public key and a handle to sign with.
//
// Ed25519 and ML-DSA-44 keys are supported. The other ML-DSA parameter sets
// KMS offers are not: C2SP signed-note assigns an algorithm identifier to
// ML-DSA-44 and to nothing else, so a key of another size could be signed with
// but not named in a note or a policy.
package note

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"filippo.io/mldsa"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// crc32cTable is the CRC32C (Castagnoli) table required by GCP KMS integrity checks.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// kmsSigner implements crypto.Signer using a GCP Cloud KMS key. pub is an
// ed25519.PublicKey or an *mldsa.PublicKey.
type kmsSigner struct {
	client       *kms.KeyManagementClient
	resourceName string
	pub          crypto.PublicKey
}

// Public returns the public key cached from KMS.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the given message using GCP Cloud KMS.
//
// Both algorithms sign the message itself rather than a digest of it -- KMS
// does any hashing internally -- so message holds the full data. The opts
// parameter is ignored.
func (s *kmsSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	digest := message
	crc := crc32.Checksum(digest, crc32cTable)

	req := &kmspb.AsymmetricSignRequest{
		Name:       s.resourceName,
		Data:       digest,
		DataCrc32C: wrapperspb.Int64(int64(crc)),
	}

	ctx := context.Background()
	resp, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("KMS AsymmetricSign: %w", err)
	}

	// Verify the response integrity.
	if !resp.VerifiedDataCrc32C {
		return nil, fmt.Errorf("KMS AsymmetricSign: request corrupted in transit")
	}
	respCRC := crc32.Checksum(resp.Signature, crc32cTable)
	if int64(respCRC) != resp.SignatureCrc32C.Value {
		return nil, fmt.Errorf("KMS AsymmetricSign: response corrupted in transit")
	}

	// Verify the signature against the cached public key as a defence-in-depth
	// check against KMS misbehaviour or key version confusion.
	switch pub := s.pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, digest, resp.Signature) {
			return nil, fmt.Errorf("KMS AsymmetricSign: signature does not verify against cached public key")
		}
	case *mldsa.PublicKey:
		if err := mldsa.Verify(pub, digest, resp.Signature, nil); err != nil {
			return nil, fmt.Errorf("KMS AsymmetricSign: signature does not verify against cached public key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported KMS public key type: %T", s.pub)
	}

	return resp.Signature, nil
}

// newKMSSigner creates a kmsSigner by connecting to GCP KMS, reading the key
// version's algorithm, and fetching the public key in the format that
// algorithm requires. It returns the signature type the key signs as.
func newKMSSigner(ctx context.Context, resourceName string) (*kmsSigner, SigType, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("creating KMS client: %w", err)
	}

	// The algorithm decides how to ask for the public key: a PQC key must name
	// a format, and errors if the format is left unspecified.
	ckv, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: resourceName,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("fetching KMS key version: %w", err)
	}

	switch ckv.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519:
		pub, err := kmsEd25519PublicKey(ctx, client, resourceName)
		if err != nil {
			return nil, 0, err
		}
		// The caller's role decides between 0x01 and 0x04; see NewKMSSigner.
		return &kmsSigner{client: client, resourceName: resourceName, pub: pub}, 0, nil

	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44:
		pub, err := kmsMLDSA44PublicKey(ctx, client, resourceName)
		if err != nil {
			return nil, 0, err
		}
		return &kmsSigner{client: client, resourceName: resourceName, pub: pub}, MLDSA44, nil

	default:
		return nil, 0, fmt.Errorf("unsupported KMS key algorithm %s: want EC_SIGN_ED25519 or PQ_SIGN_ML_DSA_44", ckv.Algorithm)
	}
}

// kmsEd25519PublicKey fetches an Ed25519 public key, which KMS returns as
// PEM-wrapped PKIX by default.
func kmsEd25519PublicKey(ctx context.Context, client *kms.KeyManagementClient, resourceName string) (ed25519.PublicKey, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: resourceName})
	if err != nil {
		return nil, fmt.Errorf("fetching KMS public key: %w", err)
	}

	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM public key from KMS")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing KMS public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not Ed25519, got %T", pub)
	}
	return edPub, nil
}

// kmsMLDSA44PublicKey fetches an ML-DSA-44 public key. A PQC key must name its
// format, and NIST_PQC is the key material as FIPS 204 defines it, which is
// what mldsa.NewPublicKey reads.
func kmsMLDSA44PublicKey(ctx context.Context, client *kms.KeyManagementClient, resourceName string) (*mldsa.PublicKey, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name:            resourceName,
		PublicKeyFormat: kmspb.PublicKey_NIST_PQC,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching KMS public key: %w", err)
	}
	if resp.PublicKeyFormat != kmspb.PublicKey_NIST_PQC || resp.PublicKey == nil {
		return nil, fmt.Errorf("KMS returned public key format %s, want NIST_PQC", resp.PublicKeyFormat)
	}

	data := resp.PublicKey.Data
	if crc := resp.PublicKey.Crc32CChecksum; crc != nil && int64(crc32.Checksum(data, crc32cTable)) != crc.Value {
		return nil, fmt.Errorf("KMS GetPublicKey: response corrupted in transit")
	}

	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), data)
	if err != nil {
		return nil, fmt.Errorf("parsing KMS ML-DSA-44 public key: %w", err)
	}
	return pub, nil
}

// NewKMSSigner creates a Signer backed by a GCP KMS key.
// The kmsResourceName should be a full KMS CryptoKeyVersion resource name like:
//
//	projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
//
// It may optionally start with a "gcpkms://" prefix, which will be stripped.
// The name parameter is the signer name used in the signed note format.
//
// The signature type comes from the key's own algorithm. An Ed25519 key signs
// as 0x01 or 0x04 according to the role; an ML-DSA-44 key signs as 0x06 in
// either, since signed-note gives that construction one identifier and the
// role does not change it.
func NewKMSSigner(ctx context.Context, name string, kmsResourceName string, role KeyRole) (*Signer, error) {
	// Strip optional gcpkms:// prefix.
	kmsResourceName = strings.TrimPrefix(kmsResourceName, "gcpkms://")

	ks, keySigType, err := newKMSSigner(ctx, kmsResourceName)
	if err != nil {
		return nil, err
	}

	sigType := keySigType
	if sigType == 0 {
		switch role {
		case RoleOrigin:
			sigType = Ed25519Origin
		case RoleCosigner:
			sigType = Ed25519Cosigner
		default:
			return nil, fmt.Errorf("unsupported role: %d", role)
		}
	}

	return &Signer{
		Name:    name,
		SigType: sigType,
		Role:    role,
		hash:    keyHash(name, pubKeyBytes(ks.pub), byte(sigType)),
		signer:  ks,
		pub:     ks.pub,
		seed:    nil, // KMS-backed signers have no local seed.
	}, nil
}
