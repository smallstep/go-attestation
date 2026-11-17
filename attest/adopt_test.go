package attest

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

func TestCheckAdoptable(t *testing.T) {
	ecc := func(curve tpm2.EllipticCurve, attrs tpm2.KeyProp) tpm2.Public {
		return tpm2.Public{Type: tpm2.AlgECC, Attributes: attrs, ECCParameters: &tpm2.ECCParams{CurveID: curve}}
	}
	rsa := func(bits uint16, attrs tpm2.KeyProp) tpm2.Public {
		return tpm2.Public{Type: tpm2.AlgRSA, Attributes: attrs, RSAParameters: &tpm2.RSAParams{KeyBits: bits}}
	}
	signing := adoptableAttributes | tpm2.FlagUserWithAuth

	for _, tc := range []struct {
		name    string
		pub     tpm2.Public
		config  KeyConfig
		wantErr bool
	}{
		{"P-256 signing key as ECDSA 256", ecc(tpm2.CurveNISTP256, signing), KeyConfig{Algorithm: ECDSA, Size: 256}, false},
		{"any algorithm when none is asked for", rsa(2048, signing), KeyConfig{}, false},
		{"RSA 2048 as RSA 2048", rsa(2048, signing), KeyConfig{Algorithm: RSA, Size: 2048}, false},
		{"RSA of any size when none is asked for", rsa(3072, signing), KeyConfig{Algorithm: RSA}, false},
		{"another curve", ecc(tpm2.CurveNISTP384, signing), KeyConfig{Algorithm: ECDSA, Size: 256}, true},
		{"another algorithm", rsa(2048, signing), KeyConfig{Algorithm: ECDSA, Size: 256}, true},
		{"another RSA size", rsa(3072, signing), KeyConfig{Algorithm: RSA, Size: 2048}, true},
		{"a restricted key, such as an AK", rsa(2048, signing|tpm2.FlagRestricted), KeyConfig{}, true},
		{"a key that can leave the TPM", ecc(tpm2.CurveNISTP256, signing&^tpm2.FlagFixedTPM), KeyConfig{}, true},
		{"a key imported rather than generated", ecc(tpm2.CurveNISTP256, signing&^tpm2.FlagSensitiveDataOrigin), KeyConfig{}, true},
		{"a key that cannot sign", ecc(tpm2.CurveNISTP256, signing&^tpm2.FlagSign), KeyConfig{}, true},
		{"a size with no algorithm", ecc(tpm2.CurveNISTP256, signing), KeyConfig{Size: 256}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAdoptable(tc.pub, &tc.config)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkAdoptable() = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

func TestAdoptKeyRequiresAName(t *testing.T) {
	if _, err := (&TPM{}).AdoptKey(nil, &KeyConfig{}); err == nil {
		t.Fatal("AdoptKey() with no name succeeded")
	}
}

func TestAdoptKeyUnsupported(t *testing.T) {
	// The Linux TPMs keep keys as blobs, never under a name.
	_, err := (&TPM{tpm: &wrappedTPM20{}}).AdoptKey(nil, &KeyConfig{Name: "app-key"})
	if !errors.Is(err, ErrAdoptUnsupported) {
		t.Fatalf("AdoptKey() = %v, want ErrAdoptUnsupported", err)
	}
}
