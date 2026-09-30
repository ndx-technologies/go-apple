package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

var (
	oidAppleAppAttestNonce     = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	AAGUIDAppAttestDevelopment = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'}
	AAGUIDAppAttestSandbox     = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 's', 'a', 'n', 'd', 'b', 'o', 'x'}
	AAGUIDAppAttest            = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0}
)

type AttestationVerifier struct {
	roots    *x509.CertPool
	rpidHash [32]byte
}

func NewAttestationVerifier(roots *x509.CertPool, teamID, bundleID string) AttestationVerifier {
	return AttestationVerifier{
		roots:    roots,
		rpidHash: sha256.Sum256([]byte(teamID + "." + bundleID)),
	}
}

func (a *AttestationObject) IsDevelopment() bool { return a.AuthData.AAGUID != AAGUIDAppAttest }

// VerifyAttestation verifies attestation object according to Apple documentation.
// Returns ECDSA P-256 public key and receipt on success.
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
func (v AttestationVerifier) VerifyAttestation(attestation *AttestationObject, keyID, clientDataHash []byte) (publicKey *ecdsa.PublicKey, receipt []byte, err error) {
	if !attestation.AuthData.Flags.IsAttestedCredentialDataPresent() {
		return nil, nil, errors.New("missing attested credential data flag")
	}

	// get x5c certificates
	if len(attestation.AttStatement.X5c) < 2 {
		return nil, nil, errors.New("x5c: requires at least 2 certificates")
	}

	intermediates := x509.NewCertPool()
	var credCert *x509.Certificate

	for i, cb := range attestation.AttStatement.X5c {
		cert, err := x509.ParseCertificate(cb)
		if err != nil {
			return nil, nil, err
		}

		if i == 0 {
			credCert = cert
		} else {
			intermediates.AddCert(cert)
		}
	}

	// 1.
	// Go requires server auth when no key usage is given, and App Attest
	// certificates are not issued for one, so every chain fails without this.
	if _, err := credCert.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, nil, err
	}

	// 2.
	nonceData := append(attestation.RawAuthData, clientDataHash...)

	// 3.
	nonce := sha256.Sum256(nonceData)

	// 4.
	nonceFromCert, err := extractNonceFromCert(credCert)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(nonce[:], nonceFromCert) {
		return nil, nil, &ErrUnexpectedNonce{Nonce: nonce}
	}

	// 5.
	publicKey, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey == nil {
		return nil, nil, errors.New("public key is not ECDSA")
	}

	ecdhKey, err := publicKey.ECDH()
	if err != nil {
		return nil, nil, err
	}
	pubKeyHash := sha256.Sum256(ecdhKey.Bytes())
	if !bytes.Equal(pubKeyHash[:], keyID) {
		return nil, nil, &ErrUnexpectedKeyID{KeyID: keyID}
	}

	// 6.
	if attestation.AuthData.RPIDHash != v.rpidHash {
		return nil, nil, &ErrUnexpectedRPID{RPIDHash: attestation.AuthData.RPIDHash}
	}

	// 7.
	if attestation.AuthData.Counter != 0 {
		return nil, nil, errors.New("counter must be 0")
	}

	// 8.
	if attestation.AuthData.AAGUID != AAGUIDAppAttest && attestation.AuthData.AAGUID != AAGUIDAppAttestDevelopment && attestation.AuthData.AAGUID != AAGUIDAppAttestSandbox {
		return nil, nil, &ErrUnexpectedAAGUID{AAGUID: attestation.AuthData.AAGUID}
	}

	// 9.
	if !bytes.Equal(attestation.AuthData.CredentialID, keyID) {
		return nil, nil, errors.New("credentialID does not match keyID")
	}

	receipt = attestation.AttStatement.Receipt
	if len(receipt) == 0 {
		return nil, nil, errors.New("receipt not found in attestation statement")
	}

	return publicKey, receipt, nil
}

func extractNonceFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAppleAppAttestNonce) {
			// DER-encoded ASN.1 sequence containing single octet string
			var seq []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
				return nil, err
			}
			if len(seq) == 0 {
				return nil, errors.New("empty sequence")
			}
			var octet asn1.RawValue
			if _, err := asn1.Unmarshal(seq[0].Bytes, &octet); err != nil {
				return nil, err
			}
			return octet.Bytes, nil
		}
	}
	return nil, errors.New("nonce extension not found")
}

type ErrUnexpectedKeyID struct{ KeyID []byte }

func (e *ErrUnexpectedKeyID) Error() string { return "unexpected keyID: " + string(e.KeyID) }

type ErrUnexpectedNonce struct{ Nonce [32]byte }

func (e *ErrUnexpectedNonce) Error() string { return "unexpected mismatch: " + string(e.Nonce[:]) }

type ErrUnexpectedAAGUID struct{ AAGUID [16]byte }

func (e *ErrUnexpectedAAGUID) Error() string { return "unexpected AAGUID: " + string(e.AAGUID[:]) }

type ErrUnexpectedRPID struct{ RPIDHash [32]byte }

func (e *ErrUnexpectedRPID) Error() string { return "unexpected RPID hash: " + string(e.RPIDHash[:]) }
