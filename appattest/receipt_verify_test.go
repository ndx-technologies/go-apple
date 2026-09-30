package appattest_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ndx-technologies/go-apple/appattest"
)

//go:embed testdata/attestation_object.bin
var attestationObjectBytesVerify []byte

//go:embed testdata/AppleRootCA-G3.cer
var appleRootCAG3DER []byte

const (
	verifyTestTeamID   = "0352187391"
	verifyTestBundleID = "com.apple.example_app_attest"
)

func TestReceiptVerifier_VerifyReceipt(t *testing.T) {
	// Use Apple Root CA - G3 for receipt verification
	// (different from App Attestation Root CA used for attestation objects)
	roots := x509.NewCertPool()
	rootCert, err := x509.ParseCertificate(appleRootCAG3DER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(rootCert)

	// extract receipt from attestation object
	var attestationObject appattest.AttestationObject
	if err := attestationObject.UnmarshalBinary(attestationObjectBytesVerify); err != nil {
		t.Fatal(err)
	}

	receiptBytes := attestationObject.AttStatement.Receipt
	if len(receiptBytes) == 0 {
		t.Fatal("receipt is empty in attestation object")
	}

	var receipt appattest.Receipt
	if err := receipt.UnmarshalBinary(receiptBytes); err != nil {
		t.Fatal(err)
	}

	// extract attested public key from attestation object credential cert
	credCert, err := x509.ParseCertificate(attestationObject.AttStatement.X5c[0])
	if err != nil {
		t.Fatal(err)
	}
	attestedPubKey, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("credential cert public key is not ECDSA")
	}

	t.Run("ok", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

			verifier := appattest.NewReceiptVerifier(roots, verifyTestTeamID, verifyTestBundleID)
			verifier.Config.MaxCreationAge = 0

			if err := verifier.VerifyReceipt(receipt, attestedPubKey); err != nil {
				t.Error(err)
			}
		})
	})

	t.Run("wrong team id", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

			verifier := appattest.NewReceiptVerifier(roots, "WRONGTEAMID", verifyTestBundleID)
			verifier.Config.MaxCreationAge = 0

			err := verifier.VerifyReceipt(receipt, nil)
			if err == nil {
				t.Error("expected error for wrong app ID")
			}

			if _, ok := errors.AsType[*appattest.ErrUnexpectedAppID](err); !ok {
				t.Fatal(err)
			}
		})
	})

	t.Run("when no root is trusted, then the chain fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

			verifier := appattest.NewReceiptVerifier(x509.NewCertPool(), "WRONGTEAMID", verifyTestBundleID)
			verifier.Config.MaxCreationAge = 0

			err := verifier.VerifyReceipt(receipt, nil)
			if err == nil {
				t.Error("expected error for wrong app ID")
			}
			if !strings.Contains(err.Error(), "x509") {
				t.Error("expected x509 error, got:", err)
			}
		})
	})

	// TestReceiptVerifier_CertificateKeyUsages verifies that receipt certificates
	// can be verified regardless of their ExtKeyUsage settings. Go's x509.Verify()
	// defaults to requiring ExtKeyUsageServerAuth if KeyUsages is not specified,
	// but App Attest certificates are not issued for server authentication.
	t.Run("certificate key usages", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

			// Log root cert ExtKeyUsage for documentation
			t.Logf("Root cert ExtKeyUsage: %v", rootCert.ExtKeyUsage)

			// Verification should succeed even though certificates may not have
			// ExtKeyUsageServerAuth (Go's default requirement when KeyUsages not set)
			verifier := appattest.NewReceiptVerifier(roots, verifyTestTeamID, verifyTestBundleID)
			verifier.Config.MaxCreationAge = 0

			if err := verifier.VerifyReceipt(receipt, attestedPubKey); err != nil {
				t.Errorf("verification should succeed with KeyUsages=ExtKeyUsageAny: %v", err)
			}
		})
	})
}
