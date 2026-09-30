package appattest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

type ReceiptVerifierConfig struct {
	MaxCreationAge time.Duration // max age of creation time, Apple recommends 5 minutes for replay attack prevention
}

func (s ReceiptVerifierConfig) WithDefaults() ReceiptVerifierConfig {
	if s.MaxCreationAge == 0 {
		s.MaxCreationAge = time.Minute * 5
	}
	return s
}

type ReceiptVerifier struct {
	Config ReceiptVerifierConfig
	roots  *x509.CertPool
	appID  string // TeamID + "." + BundleID
}

func NewReceiptVerifier(roots *x509.CertPool, teamID, bundleID string) ReceiptVerifier {
	return ReceiptVerifier{
		roots: roots,
		appID: teamID + "." + bundleID,
	}
}

// VerifyReceipt verifies App Attest receipt according to Apple documentation.
// https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk
func (v ReceiptVerifier) VerifyReceipt(receipt Receipt, attestedPublicKey *ecdsa.PublicKey) error {
	// 1-2. Verify signature and certificate chain
	if err := v.verifyCertificateChainAndSignature(receipt); err != nil {
		return err
	}

	// 3. Parse ASN.1 structure - already done in UnmarshalBinary

	// 4.
	if receipt.AppID != v.appID {
		return &ErrUnexpectedAppID{AppID: receipt.AppID, Expected: v.appID}
	}

	// 5.
	if v.Config.MaxCreationAge > 0 {
		if time.Since(receipt.CreationTime) > v.Config.MaxCreationAge {
			return &ErrReceiptTooOld{CreationTime: receipt.CreationTime, MaxAge: v.Config.MaxCreationAge}
		}
	}

	// 6.
	if attestedPublicKey == nil {
		return errors.New("attested public key is nil")
	}

	attestedPubKeyFromReceipt, err := x509.ParsePKIXPublicKey(receipt.AttestedPubKey)
	if err != nil {
		// Field 3 can be a Certificate containing the public key
		if cert, errCert := x509.ParseCertificate(receipt.AttestedPubKey); errCert == nil {
			attestedPubKeyFromReceipt = cert.PublicKey
		} else {
			return err
		}
	}

	ecdsaKey, ok := attestedPubKeyFromReceipt.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("attested public key in receipt is not ECDSA")
	}

	if !ecdsaKey.Equal(attestedPublicKey) {
		return errors.New("attested public key mismatch")
	}

	return nil
}

func (v ReceiptVerifier) verifyCertificateChainAndSignature(receipt Receipt) error {
	if len(receipt.RawCertificates) == 0 {
		return errors.New("no certificates in receipt")
	}

	certs := make([]*x509.Certificate, 0, len(receipt.RawCertificates))
	for _, der := range receipt.RawCertificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}

	leaf := certs[0]

	// Go requires server auth when no key usage is given, and App Attest
	// certificates are not issued for one, so every chain fails without this.
	opts := x509.VerifyOptions{
		Roots:       v.roots,
		CurrentTime: receipt.CreationTime, // use receipt creation time for validation
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if len(certs) > 1 {
		opts.Intermediates = x509.NewCertPool()
		// drop root cert reported in receipt. use our own root.
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	if _, err := leaf.Verify(opts); err != nil {
		return err
	}

	return v.verifySignature(receipt, leaf)
}

// signerInfo is PKCS#7 SignerInfo structure
type signerInfo struct {
	Version            int
	IssuerAndSerial    issuerAndSerialNumber
	DigestAlgorithm    pkixAlgorithmIdentifier
	AuthenticatedAttrs asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncAlg       pkixAlgorithmIdentifier
	EncryptedDigest    []byte
	UnauthAttrs        asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

func (v ReceiptVerifier) verifySignature(receipt Receipt, cert *x509.Certificate) error {
	rest := receipt.SignerInfos
	signerCount := 0
	for len(rest) > 0 {
		var si signerInfo
		var err error
		rest, err = asn1.Unmarshal(rest, &si)
		if err != nil {
			return err
		}
		signerCount++

		// determine hash function from digest algorithm
		var hashFunc crypto.Hash
		switch {
		case si.DigestAlgorithm.Algorithm.Equal(oidSHA256):
			hashFunc = crypto.SHA256
		case si.DigestAlgorithm.Algorithm.Equal(oidSHA1):
			hashFunc = crypto.SHA1
		default:
			continue
		}

		h := hashFunc.New()

		// if authenticated attributes present, hash those; otherwise hash content
		if len(si.AuthenticatedAttrs.Bytes) > 0 {
			// authenticated attributes are hashed as SET (tag 0x31)
			attrBytes := si.AuthenticatedAttrs.FullBytes
			if len(attrBytes) > 0 && attrBytes[0] == 0xa0 {
				attrBytes = append([]byte{0x31}, attrBytes[1:]...)
			}
			h.Write(attrBytes)
		} else {
			// No authenticated attributes - hash the raw content bytes
			// This is the OCTET STRING content from encapContentInfo
			h.Write(receipt.ContentInfoBytes)
		}
		digest := h.Sum(nil)

		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, hashFunc, digest, si.EncryptedDigest); err == nil {
				return nil
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, digest, si.EncryptedDigest) {
				return nil
			}

			// Try double hash (Apple App Attest often signs the hash of the data, effectively double hashing)
			// See assertion_verify.go for similar behavior.
			if hashFunc == crypto.SHA256 {
				digest2 := sha256.Sum256(digest)
				if ecdsa.VerifyASN1(pub, digest2[:], si.EncryptedDigest) {
					return nil
				}
			}
		}
	}

	return errors.New("no valid signer found in receipt")
}

type ErrUnexpectedAppID struct {
	AppID    string
	Expected string
}

func (e *ErrUnexpectedAppID) Error() string { return "unexpected app id (team id, bundle id)" }

type ErrReceiptTooOld struct {
	CreationTime time.Time
	MaxAge       time.Duration
}

func (e *ErrReceiptTooOld) Error() string {
	return "receipt too old, created_at: " + e.CreationTime.String()
}
