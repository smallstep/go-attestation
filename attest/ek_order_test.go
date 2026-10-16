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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestProviderEKFirst(t *testing.T) {
	rsa2048 := mustGenerateRSAKey(t, 2048)
	rsa3072 := mustGenerateRSAKey(t, 3072)
	p256 := mustGenerateECDSAKey(t, elliptic.P256())
	p384 := mustGenerateECDSAKey(t, elliptic.P384())

	rsa2048Cert := testEKCert("rsa2048", rsa2048)
	rsa3072Cert := testEKCert("rsa3072", rsa3072)
	p256Cert := testEKCert("p256", p256)
	p384Cert := testEKCert("p384", p384)

	type wantEK struct {
		public crypto.PublicKey
		cert   *x509.Certificate
	}

	tests := []struct {
		name        string
		provider    crypto.PublicKey
		certs       []*x509.Certificate
		want        []wantEK
		wantMatched bool
	}{
		{
			// ST33KTPM2XSPI: certificates for all four EK profiles, listed
			// with RSA 3072 first; the provider activates with RSA 2048.
			name:     "provider key certified but not listed first",
			provider: rsa2048,
			certs:    []*x509.Certificate{rsa3072Cert, rsa2048Cert, p384Cert, p256Cert},
			want: []wantEK{
				{rsa2048, rsa2048Cert},
				{rsa3072, rsa3072Cert},
				{p384, p384Cert},
				{p256, p256Cert},
			},
			wantMatched: true,
		},
		{
			// Nuvoton NPCT75x: certificates for RSA 3072 and P-384 only; the
			// provider's RSA 2048 EK has none.
			name:     "provider key not certified",
			provider: rsa2048,
			certs:    []*x509.Certificate{rsa3072Cert, p384Cert},
			want: []wantEK{
				{rsa2048, nil},
				{rsa3072, rsa3072Cert},
				{p384, p384Cert},
			},
			wantMatched: false,
		},
		{
			name:     "single certified EK",
			provider: rsa2048,
			certs:    []*x509.Certificate{rsa2048Cert},
			want: []wantEK{
				{rsa2048, rsa2048Cert},
			},
			wantMatched: true,
		},
		{
			name:     "provider key already first",
			provider: rsa2048,
			certs:    []*x509.Certificate{rsa2048Cert, p256Cert},
			want: []wantEK{
				{rsa2048, rsa2048Cert},
				{p256, p256Cert},
			},
			wantMatched: true,
		},
		{
			name:     "no certificates",
			provider: rsa2048,
			want: []wantEK{
				{rsa2048, nil},
			},
			wantMatched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched := providerEKFirst(tt.provider, tt.certs)
			if matched != tt.wantMatched {
				t.Errorf("providerEKFirst() matched = %v, want %v", matched, tt.wantMatched)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("providerEKFirst() returned %d EKs, want %d", len(got), len(tt.want))
			}
			for i, w := range tt.want {
				pub, ok := got[i].Public.(interface{ Equal(crypto.PublicKey) bool })
				if !ok || !pub.Equal(w.public) {
					t.Errorf("EK %d: unexpected public key %T", i, got[i].Public)
				}
				if got[i].Certificate != w.cert {
					t.Errorf("EK %d: certificate = %v, want %v", i, certName(got[i].Certificate), certName(w.cert))
				}
				if got[i].CertificateURL != "" {
					t.Errorf("EK %d: unexpected certificate URL %q", i, got[i].CertificateURL)
				}
			}
		})
	}
}

func mustGenerateRSAKey(t *testing.T, bits int) *rsa.PublicKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d) failed: %v", bits, err)
	}
	return &k.PublicKey
}

func mustGenerateECDSAKey(t *testing.T, c elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(%s) failed: %v", c.Params().Name, err)
	}
	return &k.PublicKey
}

// testEKCert returns a certificate carrying pub. providerEKFirst only looks at
// the public key, so the certificate does not need to be signed.
func testEKCert(name string, pub crypto.PublicKey) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: name}, PublicKey: pub}
}

func certName(c *x509.Certificate) string {
	if c == nil {
		return "<nil>"
	}
	return c.Subject.CommonName
}
