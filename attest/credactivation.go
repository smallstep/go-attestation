// Copyright 2026 Smallstep Labs, Inc.
// Copyright (c) 2018, Google LLC All rights reserved.
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
//
// This file is heavily based on https://github.com/google/go-tpm/blob/main/legacy/tpm2/credactivation/credential_activation.go,
// but fixes an issue with the hashing algorithm used when generating a credential
// for a TPM. Also see https://github.com/google/go-tpm/issues/121.

package attest

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Labels for use in key derivation or OAEP encryption.
const (
	labelIdentity  = "IDENTITY"
	labelStorage   = "STORAGE"
	labelIntegrity = "INTEGRITY"
)

// generateCredentialActivation returns a TPM2B_ID_OBJECT and a
// TPM2B_ENCRYPTED_SECRET for use in credential activation.
//
// It is equivalent to credactivation.Generate from go-tpm, except that the hash
// algorithm is taken from the EK rather than from the name of the object being
// activated. The TPM protects the credential with the name algorithm of the
// protector -- the EK -- so passing the AK's produces a blob the TPM cannot
// unwrap whenever the two differ, which is the case for every EK in the TCG
// high range above RSA 2048 and NIST P-256.
//
// The name is still the name of the object being activated: it is an input to
// KDFa and to the integrity HMAC, never a source of algorithms.
//
// This implements Credential Protection as defined in section 24 of the TPM 2.0
// specification, part 1.
func generateCredentialActivation(name *tpm2.HashValue, ek crypto.PublicKey, ekNameAlg tpm2.Algorithm, symBlockSize int, secret []byte, rnd io.Reader) ([]byte, []byte, error) {
	hashAlg, err := ekNameAlg.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("EK name algorithm: %v", err)
	}

	var seed, encSecret []byte
	switch ekKey := ek.(type) {
	case *ecdh.PublicKey:
		seed, encSecret, err = createECSeed(ekKey, ekNameAlg, hashAlg, rnd)
		if err != nil {
			return nil, nil, fmt.Errorf("creating seed: %v", err)
		}
	case *ecdsa.PublicKey:
		ecdhKey, err := ekKey.ECDH()
		if err != nil {
			return nil, nil, fmt.Errorf("transmuting ecdsa key to ecdh key: %v", err)
		}
		return generateCredentialActivation(name, ecdhKey, ekNameAlg, symBlockSize, secret, rnd)
	case *rsa.PublicKey:
		seed, encSecret, err = createRSASeed(ekKey, hashAlg, symBlockSize, rnd)
		if err != nil {
			return nil, nil, fmt.Errorf("creating seed: %v", err)
		}
	default:
		return nil, nil, errors.New("only RSA and EC public keys are supported for credential activation")
	}

	// Generate the encrypted credential by convolving the seed with the digest of
	// the name of the object being activated, and using the result as the key to
	// encrypt the secret. See section 24.4 of the TPM 2.0 specification, part 1.
	nameEncoded, err := name.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding name: %v", err)
	}
	symmetricKey, err := tpm2.KDFa(ekNameAlg, seed, labelStorage, nameEncoded, nil, symBlockSize*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating symmetric key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetric cipher setup: %v", err)
	}
	cv, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("generating cv (TPM2B_Digest): %v", err)
	}

	// IV is all null bytes. encIdentity represents the encrypted credential.
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, c.BlockSize())).XORKeyStream(encIdentity, cv)

	// Generate the integrity HMAC, which is used to protect the integrity of the
	// encrypted structure. See section 24.5 of the TPM 2.0 specification, part 1.
	macKey, err := tpm2.KDFa(ekNameAlg, seed, labelIntegrity, nil, nil, hashAlg.Size()*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating HMAC key: %v", err)
	}

	mac := hmac.New(hashAlg.New, macKey)
	mac.Write(encIdentity)
	mac.Write(nameEncoded)
	integrityHMAC := mac.Sum(nil)

	idObject := &tpm2.IDObject{
		IntegrityHMAC: integrityHMAC,
		EncIdentity:   encIdentity,
	}
	id, err := tpmutil.Pack(idObject)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding IDObject: %v", err)
	}

	packedID, err := tpmutil.Pack(tpmutil.U16Bytes(id))
	if err != nil {
		return nil, nil, fmt.Errorf("packing id: %v", err)
	}
	packedEncSecret, err := tpmutil.Pack(tpmutil.U16Bytes(encSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("packing encSecret: %v", err)
	}

	return packedID, packedEncSecret, nil
}

func createRSASeed(ek *rsa.PublicKey, hashAlg crypto.Hash, symBlockSize int, rnd io.Reader) ([]byte, []byte, error) {
	// The seed length should match the keysize used by the EKs symmetric cipher.
	// For typical RSA EKs, this will be 128 bits (16 bytes).
	// Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
	seed := make([]byte, symBlockSize)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, fmt.Errorf("generating seed: %v", err)
	}

	// Encrypt the seed value using the provided public key.
	// See annex B, section 10.4 of the TPM specification revision 2 part 1.
	label := append([]byte(labelIdentity), 0)
	encryptedSeed, err := rsa.EncryptOAEP(hashAlg.New(), rnd, ek, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encrypted seed: %v", err)
	}

	encryptedSeed, err = tpmutil.Pack(encryptedSeed)
	return seed, encryptedSeed, err
}

func createECSeed(ek *ecdh.PublicKey, ekNameAlg tpm2.Algorithm, hashAlg crypto.Hash, rnd io.Reader) (seed, encryptedSeed []byte, err error) {
	ephemeralPriv, err := ek.Curve().GenerateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	ephemeralX, ephemeralY := deconstructECDHPublicKey(ephemeralPriv.PublicKey())

	z, err := ephemeralPriv.ECDH(ek)
	if err != nil {
		return nil, nil, err
	}

	ekX, _ := deconstructECDHPublicKey(ek)

	seed, err = tpm2.KDFe(
		ekNameAlg,
		z,
		labelIdentity,
		ephemeralX,
		ekX,
		hashAlg.Size()*8)
	if err != nil {
		return nil, nil, err
	}
	encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(ephemeralX), tpmutil.U16Bytes(ephemeralY))
	return seed, encryptedSeed, err
}

func deconstructECDHPublicKey(key *ecdh.PublicKey) (x []byte, y []byte) {
	b := key.Bytes()[1:]
	return b[:len(b)/2], b[len(b)/2:]
}
