package appattest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ndx-technologies/go-apple/appattest"
)

//go:embed testdata/Apple_App_Attestation_Root_CA.pem
var appleAppAttestRootCAPEM []byte

//go:embed testdata/attestation_object.bin
var attestationObjectBytes []byte

//go:embed testdata/leaf_cert.bin
var expectedLeafCert []byte

//go:embed testdata/intermediate_cert.bin
var expectedIntermediateCert []byte

const (
	// Example data from Apple's Attestation Object Validation Guide.
	// More files from Apple guide can be found in testdata (base64 decoded).
	// https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
	exampleTeamID               = "0352187391"
	exampleBundleID             = "com.apple.example_app_attest"
	exampleKeyIDBase64          = "bSrEhF8TIzIvWSPwvZ0i2+UOBre4ASH84rK15m6emNY="
	expectedNonceBase64         = "+20WKnF+yrF3iQBQb6lNZ+4MHcPUWxLN3oG+/Fblt+s="
	expectedRPIDHashBase64      = "FVhAM8lQuf6dUUziohGjJtcaprEBSrTG+i+9qdmqGKY="
	expectedPublicKeyHashBase64 = "bSrEhF8TIzIvWSPwvZ0i2+UOBre4ASH84rK15m6emNY="
)

var (
	clientDataHash = []byte("test_server_challenge") // In Apple's example, clientDataHash is the raw challenge bytes even if it does not look like a hash
)

func TestVerifyAttestation_ok(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(appleAppAttestRootCAPEM) {
			t.Error("failed to add root CA")
		}

		keyID, err := base64.StdEncoding.DecodeString(exampleKeyIDBase64)
		if err != nil {
			t.Error(err)
		}

		var attestationObject appattest.AttestationObject
		if err := attestationObject.UnmarshalBinary(attestationObjectBytes); err != nil {
			t.Error(err)
		}

		verifier := appattest.NewAttestationVerifier(roots, exampleTeamID, exampleBundleID)
		publicKey, receipt, err := verifier.VerifyAttestation(&attestationObject, keyID, clientDataHash)
		if err != nil {
			t.Error(err)
		}

		if publicKey == nil {
			t.Error("public key is nil")
		}

		if len(receipt) == 0 {
			t.Error("receipt is empty")
		}

		if attestationObject.IsDevelopment() {
			t.Error("expected production environment")
		}
	})
}

func TestVerifyAttestation_RPIDHashComputation(t *testing.T) {
	appID := exampleTeamID + "." + exampleBundleID
	rpidHash := sha256.Sum256([]byte(appID))

	expectedRPIDHash, err := base64.StdEncoding.DecodeString(expectedRPIDHashBase64)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(rpidHash[:], expectedRPIDHash) {
		t.Error(rpidHash)
	}
}

func TestVerifyAttestation_Invalid(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(appleAppAttestRootCAPEM)

		keyID, err := base64.StdEncoding.DecodeString(exampleKeyIDBase64)
		if err != nil {
			t.Error(err)
		}

		var attestationObject appattest.AttestationObject
		attestationObject.UnmarshalBinary(attestationObjectBytes)

		verifier := appattest.NewAttestationVerifier(roots, exampleTeamID, exampleBundleID)

		// wrong challenge
		wrongChallenge := sha256.Sum256([]byte("wrong_challenge"))
		if _, _, err := verifier.VerifyAttestation(&attestationObject, keyID, wrongChallenge[:]); err == nil {
			t.Error(err)
		}

		// wrong key
		wrongKeyID := make([]byte, 32)
		if _, _, err := verifier.VerifyAttestation(&attestationObject, wrongKeyID, clientDataHash); err == nil {
			t.Error(err)
		}

		// empty root CA pool
		verifierEmpty := appattest.NewAttestationVerifier(x509.NewCertPool(), exampleTeamID, exampleBundleID)
		if _, _, err := verifierEmpty.VerifyAttestation(&attestationObject, keyID, clientDataHash); err == nil {
			t.Error("expected certificate verification error")
		}

		// wrong team ID
		verifierWrongTeamID := appattest.NewAttestationVerifier(roots, "WRONGTEAMID", exampleBundleID)
		if _, _, err := verifierWrongTeamID.VerifyAttestation(&attestationObject, keyID, clientDataHash); err == nil {
			t.Error(err)
		}

		// wrong bundle ID
		verifierWrongBundleID := appattest.NewAttestationVerifier(roots, exampleTeamID, "com.wrong.bundleid")
		if _, _, err := verifierWrongBundleID.VerifyAttestation(&attestationObject, keyID, clientDataHash); err == nil {
			t.Error(err)
		}
	})
}

func TestVerifyAttestation_IntermediateValues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		var attestationObject appattest.AttestationObject
		if err := attestationObject.UnmarshalBinary(attestationObjectBytes); err != nil {
			t.Error(err)
		}

		// 2-3.
		nonceData := append(attestationObject.RawAuthData, clientDataHash...)
		nonce := sha256.Sum256(nonceData)
		expectedNonce, err := base64.StdEncoding.DecodeString(expectedNonceBase64)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(nonce[:], expectedNonce) {
			t.Error(nonce)
		}

		// 5.
		credCert, err := x509.ParseCertificate(attestationObject.AttStatement.X5c[0])
		if err != nil {
			t.Error(err)
		}
		publicKey := credCert.PublicKey.(*ecdsa.PublicKey)
		ecdhKey, err := publicKey.ECDH()
		if err != nil {
			t.Error(err)
		}
		pubKeyHash := sha256.Sum256(ecdhKey.Bytes())
		expectedPubKeyHash, err := base64.StdEncoding.DecodeString(expectedPublicKeyHashBase64)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(pubKeyHash[:], expectedPubKeyHash) {
			t.Error(pubKeyHash)
		}

		// 6.
		expectedRPIDHash, err := base64.StdEncoding.DecodeString(expectedRPIDHashBase64)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(attestationObject.AuthData.RPIDHash[:], expectedRPIDHash) {
			t.Error(attestationObject.AuthData.RPIDHash)
		}

		// 7.
		if attestationObject.AuthData.Counter != 0 {
			t.Error(attestationObject.AuthData.Counter)
		}

		// 8.
		if attestationObject.AuthData.AAGUID != appattest.AAGUIDAppAttest {
			t.Error(attestationObject.AuthData.AAGUID)
		}

		// 9.
		keyID, err := base64.StdEncoding.DecodeString(exampleKeyIDBase64)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(attestationObject.AuthData.CredentialID, keyID) {
			t.Error(attestationObject.AuthData.CredentialID)
		}
	})
}

func TestVerifyAttestation_CertificateChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		var attestationObject appattest.AttestationObject
		if err := attestationObject.UnmarshalBinary(attestationObjectBytes); err != nil {
			t.Error(err)
		}

		// Verify leaf certificate (step 1 from Apple's guide)
		if !bytes.Equal(attestationObject.AttStatement.X5c[0], expectedLeafCert) {
			t.Error("leaf certificate does not match expected")
		}

		// Verify intermediate certificate
		if !bytes.Equal(attestationObject.AttStatement.X5c[1], expectedIntermediateCert) {
			t.Error("intermediate certificate does not match expected")
		}
	})
}

// TestVerifyAttestation_CertificateKeyUsages verifies that App Attest certificates
// can be verified regardless of their ExtKeyUsage settings. Go's x509.Verify() defaults
// to requiring ExtKeyUsageServerAuth if KeyUsages is not specified, but App Attest
// certificates are not issued for server authentication. This test ensures the verifier
// correctly handles certificates that may have explicit ExtKeyUsage restrictions.
func TestVerifyAttestation_CertificateKeyUsages(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC)))

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(appleAppAttestRootCAPEM) {
			t.Fatal("failed to add root CA")
		}

		keyID, err := base64.StdEncoding.DecodeString(exampleKeyIDBase64)
		if err != nil {
			t.Fatal(err)
		}

		var attestationObject appattest.AttestationObject
		if err := attestationObject.UnmarshalBinary(attestationObjectBytes); err != nil {
			t.Fatal(err)
		}

		// Parse certificates to inspect their ExtKeyUsage
		credCert, err := x509.ParseCertificate(attestationObject.AttStatement.X5c[0])
		if err != nil {
			t.Fatal(err)
		}
		intermediateCert, err := x509.ParseCertificate(attestationObject.AttStatement.X5c[1])
		if err != nil {
			t.Fatal(err)
		}
		rootCert, err := x509.ParseCertificates(appleAppAttestRootCAPEM)
		if err != nil || len(rootCert) == 0 {
			// Root is PEM, need to decode differently
			block, _ := pem.Decode(appleAppAttestRootCAPEM)
			if block == nil {
				t.Fatal("failed to decode PEM")
			}
			rootCert = make([]*x509.Certificate, 1)
			rootCert[0], err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Log ExtKeyUsage for documentation purposes
		t.Logf("Leaf cert ExtKeyUsage: %v", credCert.ExtKeyUsage)
		t.Logf("Intermediate cert ExtKeyUsage: %v", intermediateCert.ExtKeyUsage)
		t.Logf("Root cert ExtKeyUsage: %v", rootCert[0].ExtKeyUsage)

		// Verify that the attestation passes even though certificates
		// don't have ExtKeyUsageServerAuth (Go's default requirement)
		verifier := appattest.NewAttestationVerifier(roots, exampleTeamID, exampleBundleID)
		publicKey, receipt, err := verifier.VerifyAttestation(&attestationObject, keyID, clientDataHash)
		if err != nil {
			t.Errorf("verification should succeed with KeyUsages=ExtKeyUsageAny: %v", err)
		}
		if publicKey == nil {
			t.Error("public key should not be nil")
		}
		if len(receipt) == 0 {
			t.Error("receipt should not be empty")
		}
	})
}
