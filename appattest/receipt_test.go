package appattest_test

import (
	_ "embed"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ndx-technologies/go-apple/appattest"
)

//go:embed testdata/attestation_object.bin
var attestationObjectBytesReceipt []byte

//go:embed testdata/receipt.bin
var receiptBytes []byte

const (
	receiptTestTeamID   = "0352187391"
	receiptTestBundleID = "com.apple.example_app_attest"
)

func TestReceipt_Attest_UnmarshalBinary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		var attestationObject appattest.AttestationObject
		if err := attestationObject.UnmarshalBinary(attestationObjectBytesReceipt); err != nil {
			t.Error(err)
		}

		b := attestationObject.AttStatement.Receipt
		if len(b) == 0 {
			t.Fatal("receipt is empty in attestation object")
		}

		var receipt appattest.Receipt
		if err := receipt.UnmarshalBinary(b); err != nil {
			t.Error(err)
		}

		if expectedAppID := receiptTestTeamID + "." + receiptTestBundleID; receipt.AppID != expectedAppID {
			t.Errorf("unexpected app ID: got %q, expected %q", receipt.AppID, expectedAppID)
		}

		if len(receipt.AttestedPubKey) == 0 {
			t.Error("attested public key is empty")
		}

		if len(receipt.RawCertificates) == 0 {
			t.Error("raw certificates is empty")
		}

		if receipt.ReceiptType != "ATTEST" {
			t.Error(receipt.ReceiptType)
		}

		if !receipt.CreationTime.Equal(time.Date(2024, 4, 18, 16, 14, 54, 209000000, time.UTC)) {
			t.Error(receipt.CreationTime)
		}

		if !receipt.ExpirationTime.Equal(time.Date(2024, 7, 17, 16, 14, 54, 209000000, time.UTC)) {
			t.Error(receipt.ExpirationTime)
		}
	})
}

func TestReceipt_Receipt_UnmarshalBinary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		var receipt appattest.Receipt
		if err := receipt.UnmarshalBinary(receiptBytes); err != nil {
			t.Error(err)
		}

		// Pinned by testdata/receipt.bin: the App ID is inside a PKCS#7 blob whose
		// signature covers it, so it cannot be replaced with a placeholder.
		teamID := "7M3645L2TM"
		bundleID := "com.meimei168.PriceTracker"

		if expectedAppID := teamID + "." + bundleID; receipt.AppID != expectedAppID {
			t.Errorf("unexpected app ID: got %q, expected %q", receipt.AppID, expectedAppID)
		}

		if len(receipt.AttestedPubKey) == 0 {
			t.Error("attested public key is empty")
		}

		if len(receipt.RawCertificates) == 0 {
			t.Error("raw certificates is empty")
		}

		if receipt.ReceiptType != "RECEIPT" {
			t.Error(receipt.ReceiptType)
		}

		if receipt.RiskMetric == nil || *receipt.RiskMetric != 10 {
			t.Error(receipt.RiskMetric)
		}

		if !receipt.CreationTime.Equal(time.Date(2025, 12, 22, 6, 33, 56, 681000000, time.UTC)) {
			t.Error(receipt.CreationTime)
		}

		if !receipt.ExpirationTime.Equal(time.Date(2026, 3, 22, 6, 33, 56, 681000000, time.UTC)) {
			t.Error(receipt.ExpirationTime)
		}
	})
}
