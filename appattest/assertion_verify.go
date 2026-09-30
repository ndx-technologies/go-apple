package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
)

type AssertionVerifier struct {
	rpidHash [32]byte
}

func NewAssertionVerifier(teamID, bundleID string) AssertionVerifier {
	return AssertionVerifier{
		rpidHash: sha256.Sum256([]byte(teamID + "." + bundleID)),
	}
}

// VerifyAssertion verifies assertion object.
// publicKey is ECDSA P-256 public key from attestation.
// prevCounter should be 0 for first assertion after attestation.
// challenge is the one-time challenge sent to client that should be embedded in clientData.
// Returns new counter value on success.
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
func (v AssertionVerifier) VerifyAssertion(assertion *AssertionObject, publicKey *ecdsa.PublicKey, clientData, challenge []byte, prevCounter uint32) (counter uint32, err error) {
	// 1. Compute clientDataHash as the SHA256 hash of clientData.
	clientDataHash := sha256.Sum256(clientData)

	// 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
	nonce := sha256.Sum256(append(assertion.RawAuthData, clientDataHash[:]...))

	// 3. Use the public key that you store from the attestation object to verify that the assertion's signature is valid for nonce.
	// Note: Apple's documentation says "verify signature is valid for nonce", but standard ECDSA
	// verification (e.g. SHA256withECDSA in Java/Kotlin, createVerify('SHA256') in Node.js)
	// hashes the message internally. Go's ecdsa.VerifyASN1 expects pre-hashed digest,
	// so we must hash nonce ourselves to match what Apple's Secure Enclave produces.
	//
	// Other implementations doing SHA256:
	//   - https://github.com/uebelack/node-app-attest/blob/main/src/verifyAssertion.js
	//   - https://github.com/veehaitch/devicecheck-appattest/blob/main/src/main/kotlin/ch/veehait/devicecheck/appattest/assertion/AssertionValidator.kt
	//   - https://github.com/splitsecure/go-app-attest/blob/main/appattest/verify_assertion.go
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(publicKey, digest[:], assertion.Signature) {
		return 0, errors.New("invalid signature")
	}

	// 4. Compute the SHA256 hash of the client's App ID, and verify that it matches the RP ID in the authenticator data.
	if assertion.AuthData.RPIDHash != v.rpidHash {
		return 0, errors.New("unexpected RP ID")
	}

	// 5. Verify that the authenticator data's counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
	if assertion.AuthData.Counter <= prevCounter {
		return 0, errors.New("counter not incremented")
	}

	// 6. Verify that the challenge embedded in the client data matches the earlier challenge to the client.
	if !bytes.Contains(clientData, challenge) {
		return 0, errors.New("challenge not found in clientData")
	}

	return assertion.AuthData.Counter, nil
}
