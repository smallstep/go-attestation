// Copyright 2026 Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package attest

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

// recoverCredential models the TPM side of TPM2_ActivateCredential, so that a
// generated challenge can be checked without a TPM.
//
// Everything here is derived from the EK's name algorithm, which is what the
// TPM does: the reference implementation OAEP-decrypts the seed with
// decryptKey->publicArea.nameAlg (CryptSecretDecrypt), and unwraps the
// credential with outerHash = protector->publicArea.nameAlg
// (CredentialToSecret). The name of the activated object -- the AK -- is only
// ever an input to KDFa and the HMAC, never a source of algorithms.
//
// See TPM 2.0 Library Specification, Part 1, section 24.
func recoverCredential(ekPriv crypto.PrivateKey, ekNameAlg tpm2.Algorithm, symBlockSize int, akName *tpm2.HashValue, ec *EncryptedCredential) ([]byte, error) {
	hashAlg, err := ekNameAlg.Hash()
	if err != nil {
		return nil, fmt.Errorf("EK name algorithm: %w", err)
	}

	seed, err := recoverSeed(ekPriv, hashAlg, ec.Secret)
	if err != nil {
		return nil, fmt.Errorf("recovering seed: %w", err)
	}

	akNameEncoded, err := akName.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding AK name: %w", err)
	}

	integrityHMAC, encIdentity, err := unpackIDObject(ec.Credential)
	if err != nil {
		return nil, fmt.Errorf("unpacking credential: %w", err)
	}

	macKey, err := tpm2.KDFa(ekNameAlg, seed, "INTEGRITY", nil, nil, hashAlg.Size()*8)
	if err != nil {
		return nil, fmt.Errorf("deriving HMAC key: %w", err)
	}
	mac := hmac.New(hashAlg.New, macKey)
	mac.Write(encIdentity)
	mac.Write(akNameEncoded)
	if !hmac.Equal(mac.Sum(nil), integrityHMAC) {
		return nil, fmt.Errorf("integrity HMAC does not verify")
	}

	symKey, err := tpm2.KDFa(ekNameAlg, seed, "STORAGE", akNameEncoded, nil, symBlockSize*8)
	if err != nil {
		return nil, fmt.Errorf("deriving symmetric key: %w", err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, fmt.Errorf("symmetric cipher setup: %w", err)
	}
	cv := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, make([]byte, block.BlockSize())).XORKeyStream(cv, encIdentity)

	if len(cv) < 2 {
		return nil, fmt.Errorf("decrypted credential is too short")
	}
	size := int(binary.BigEndian.Uint16(cv[:2]))
	if len(cv) < 2+size {
		return nil, fmt.Errorf("decrypted credential claims %d bytes, has %d", size, len(cv)-2)
	}
	return cv[2 : 2+size], nil
}

// recoverSeed decrypts the seed the way the TPM does: RSA-OAEP with the EK name
// algorithm for an RSA EK, ECDH plus KDFe for an EC one.
func recoverSeed(ekPriv crypto.PrivateKey, hashAlg crypto.Hash, encSecret []byte) ([]byte, error) {
	if len(encSecret) < 2 {
		return nil, fmt.Errorf("encrypted secret is too short")
	}
	blob := encSecret[2:] // strip the TPM2B size prefix
	label := append([]byte("IDENTITY"), 0)

	switch priv := ekPriv.(type) {
	case *rsa.PrivateKey:
		return rsa.DecryptOAEP(hashAlg.New(), nil, priv, blob, label)
	case *ecdsa.PrivateKey:
		x, y, err := unpackECPoint(blob)
		if err != nil {
			return nil, err
		}
		ekECDH, err := priv.ECDH()
		if err != nil {
			return nil, err
		}
		pointLen := (priv.Curve.Params().BitSize + 7) / 8
		uncompressed := make([]byte, 0, 1+2*pointLen)
		uncompressed = append(uncompressed, 4)
		uncompressed = append(uncompressed, leftPad(x, pointLen)...)
		uncompressed = append(uncompressed, leftPad(y, pointLen)...)
		ephemeral, err := ekECDH.Curve().NewPublicKey(uncompressed)
		if err != nil {
			return nil, fmt.Errorf("parsing ephemeral point: %w", err)
		}
		z, err := ekECDH.ECDH(ephemeral)
		if err != nil {
			return nil, err
		}
		alg, err := tpm2.HashToAlgorithm(hashAlg)
		if err != nil {
			return nil, err
		}
		ekX := ekECDH.PublicKey().Bytes()[1 : 1+pointLen]
		return tpm2.KDFe(alg, z, "IDENTITY", leftPad(x, pointLen), ekX, hashAlg.Size()*8)
	default:
		return nil, fmt.Errorf("unsupported EK type %T", ekPriv)
	}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// unpackIDObject splits a TPM2B_ID_OBJECT into its integrity HMAC and the
// encrypted credential.
func unpackIDObject(credential []byte) (integrityHMAC, encIdentity []byte, err error) {
	if len(credential) < 4 {
		return nil, nil, fmt.Errorf("credential is too short")
	}
	id := credential[2:] // strip the outer TPM2B size prefix
	size := int(binary.BigEndian.Uint16(id[:2]))
	if len(id) < 2+size {
		return nil, nil, fmt.Errorf("integrity HMAC claims %d bytes, has %d", size, len(id)-2)
	}
	return id[2 : 2+size], id[2+size:], nil
}

// unpackECPoint splits the two TPM2B-prefixed coordinates of an ephemeral point.
func unpackECPoint(b []byte) (x, y []byte, err error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("point is too short")
	}
	xLen := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+xLen+2 {
		return nil, nil, fmt.Errorf("point is truncated")
	}
	x = b[2 : 2+xLen]
	rest := b[2+xLen:]
	yLen := int(binary.BigEndian.Uint16(rest[:2]))
	if len(rest) < 2+yLen {
		return nil, nil, fmt.Errorf("point is truncated")
	}
	return x, rest[2 : 2+yLen], nil
}

// TestActivationParametersGenerateEKNameAlg checks that a challenge is built
// with the EK's name algorithm, by having a software model of the TPM recover
// the secret from it.
//
// The AK fixture has a SHA-256 name algorithm, so every case whose EK name
// algorithm is not SHA-256 fails if the challenge is built with the AK's.
//
// The templates come from the TCG EK Credential Profile v2.6: L-1/H-1 and H-2
// use SHA-256 with AES-128, H-3 and H-6/H-7 use SHA-384 with AES-256, and H-4
// uses SHA-512 with AES-256.
func TestActivationParametersGenerateEKNameAlg(t *testing.T) {
	for _, test := range []struct {
		name         string
		ekPriv       func(t *testing.T) crypto.PrivateKey
		ekNameAlg    tpm2.Algorithm
		symBlockSize int
		// asECDH passes the EK as an *ecdh.PublicKey instead of an
		// *ecdsa.PublicKey, which callers are free to do.
		asECDH bool
	}{
		{
			name:         "rsa-2048", // L-1, H-1
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return rsaKey(t, 2048) },
			ekNameAlg:    tpm2.AlgSHA256,
			symBlockSize: 16,
		},
		{
			name:         "rsa-3072", // H-6
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return rsaKey(t, 3072) },
			ekNameAlg:    tpm2.AlgSHA384,
			symBlockSize: 32,
		},
		{
			name:         "rsa-4096", // H-7
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return rsaKey(t, 4096) },
			ekNameAlg:    tpm2.AlgSHA384,
			symBlockSize: 32,
		},
		{
			name:         "ecdsa-P256", // H-2
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return ecdsaKey(t, elliptic.P256()) },
			ekNameAlg:    tpm2.AlgSHA256,
			symBlockSize: 16,
		},
		{
			name:         "ecdsa-P384", // H-3
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return ecdsaKey(t, elliptic.P384()) },
			ekNameAlg:    tpm2.AlgSHA384,
			symBlockSize: 32,
		},
		{
			name:         "ecdsa-P521", // H-4
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return ecdsaKey(t, elliptic.P521()) },
			ekNameAlg:    tpm2.AlgSHA512,
			symBlockSize: 32,
		},
		{
			name:         "ecdh-P384",
			ekPriv:       func(t *testing.T) crypto.PrivateKey { return ecdsaKey(t, elliptic.P384()) },
			ekNameAlg:    tpm2.AlgSHA384,
			symBlockSize: 32,
			asECDH:       true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var err error
			ekPriv := test.ekPriv(t)
			signer, ok := ekPriv.(crypto.Signer)
			if !ok {
				t.Fatalf("EK of type %T is not a crypto.Signer", ekPriv)
			}

			ekPub := signer.Public()
			if test.asECDH {
				ecdsaPub, ok := ekPub.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("EK of type %T cannot be an ECDH key", ekPub)
				}
				if ekPub, err = ecdsaPub.ECDH(); err != nil {
					t.Fatalf("ECDH() returned err: %v", err)
				}
			}

			akParams := realWorldAKParams(t)
			params := ActivationParameters{
				TPMVersion: TPMVersion20,
				AK:         akParams,
				EK:         ekPub,
			}

			secret, ec, err2 := params.Generate()
			err = err2
			if err != nil {
				t.Fatalf("Generate() returned err: %v", err)
			}

			att, err := tpm2.DecodeAttestationData(akParams.CreateAttestation)
			if err != nil {
				t.Fatalf("DecodeAttestationData() returned err: %v", err)
			}
			akName := att.AttestedCreationInfo.Name.Digest
			if akName.Alg != tpm2.AlgSHA256 {
				t.Fatalf("AK name algorithm = %v, want SHA-256", akName.Alg)
			}

			got, err := recoverCredential(ekPriv, test.ekNameAlg, test.symBlockSize, akName, ec)
			if err != nil {
				t.Fatalf("a TPM with a %v EK could not recover the secret: %v", test.ekNameAlg, err)
			}
			if !bytes.Equal(got, secret) {
				t.Errorf("recovered secret = %x, want %x", got, secret)
			}
		})
	}
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d) returned err: %v", bits, err)
	}
	return k
}

func ecdsaKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(%v) returned err: %v", curve.Params().Name, err)
	}
	return k
}
