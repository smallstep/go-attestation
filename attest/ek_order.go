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
	"crypto"
	"crypto/x509"
)

// providerEKFirst builds the EK list for a TPM whose platform key provider
// activates credentials with one specific endorsement key. On Windows the
// Platform Crypto Provider always activates with its own EK (PCP_EKPUB) and
// offers no way to choose another, so on a TPM with several EKs only that one
// can complete a credential activation challenge.
//
// The provider's key is returned first, paired with the certificate in certs
// whose public key matches it, if there is one. The remaining certificates
// follow in their original order, so callers that report every EK still see
// all of them. Callers that send a single EK to an attestation CA must send
// the first one.
//
// matched reports whether a certificate was paired with the provider's key.
func providerEKFirst(provider crypto.PublicKey, certs []*x509.Certificate) (eks []EK, matched bool) {
	pub, canCompare := provider.(interface{ Equal(crypto.PublicKey) bool })

	first := EK{Public: provider}
	rest := make([]EK, 0, len(certs))
	for _, cert := range certs {
		if !matched && canCompare && pub.Equal(cert.PublicKey) {
			first.Certificate = cert
			matched = true
			continue
		}
		rest = append(rest, EK{Certificate: cert, Public: cert.PublicKey})
	}

	return append([]EK{first}, rest...), matched
}
