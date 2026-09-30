package appattest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ndx-technologies/go-apple/appattest"
)

const (
	testTeamID   = "ABCDE12345"
	testBundleID = "com.example.app"
)

// assertionWire is the CBOR App Attest sends: a signature next to the raw
// authenticator data. The derived fields are filled in by UnmarshalBinary.
type assertionWire struct {
	Signature   []byte `cbor:"signature"`
	RawAuthData []byte `cbor:"authenticatorData"`
}

func testChallenge() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func testClientData(challenge []byte) []byte {
	return append([]byte("POST /sensitive "), challenge...)
}

// wantError pins a negative case to the validation step it is meant to reach.
// Without the message check these tests would still pass if a reordered check
// made the intended branch unreachable.
func wantError(t *testing.T, err error, contains string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected an error containing %q", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Errorf("got %q, want it to contain %q", err, contains)
	}
}

// newAssertion produces a valid assertion the way a device does, by signing with
// a key generated here. A recorded assertion could only ever replay one outcome,
// and its client data cannot be reconstructed without the original challenge, so
// generating the key is what makes every branch below reachable.
func newAssertion(t *testing.T, teamID, bundleID string, counter uint32, clientData []byte) (*appattest.AssertionObject, *ecdsa.PublicKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rpidHash := sha256.Sum256([]byte(teamID + "." + bundleID))

	rawAuthData := make([]byte, 0, 37)
	rawAuthData = append(rawAuthData, rpidHash[:]...)
	rawAuthData = append(rawAuthData, 0x00) // no attested credential data in an assertion
	rawAuthData = binary.BigEndian.AppendUint32(rawAuthData, counter)

	// The signature covers SHA256(SHA256(authenticatorData || SHA256(clientData))),
	// because Go's ecdsa expects a pre-hashed digest while Apple's Secure Enclave
	// signs the hash of the nonce.
	clientDataHash := sha256.Sum256(clientData)
	nonceInput := make([]byte, 0, len(rawAuthData)+len(clientDataHash))
	nonceInput = append(nonceInput, rawAuthData...)
	nonceInput = append(nonceInput, clientDataHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	digest := sha256.Sum256(nonce[:])

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := cbor.Marshal(assertionWire{Signature: signature, RawAuthData: rawAuthData})
	if err != nil {
		t.Fatal(err)
	}

	var assertion appattest.AssertionObject
	if err := assertion.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}

	return &assertion, key.Public().(*ecdsa.PublicKey)
}

func TestAssertionObjectUnmarshalBinary(t *testing.T) {
	t.Run("when the object is well formed, then the authenticator data is parsed", func(t *testing.T) {
		assertion, _ := newAssertion(t, testTeamID, testBundleID, 7, testClientData(testChallenge()))

		if assertion.AuthData.Counter != 7 {
			t.Error(assertion.AuthData.Counter)
		}
		if want := sha256.Sum256([]byte(testTeamID + "." + testBundleID)); assertion.AuthData.RPIDHash != want {
			t.Error(assertion.AuthData.RPIDHash)
		}
	})

	t.Run("when the authenticator data is truncated, then it is refused", func(t *testing.T) {
		encoded, err := cbor.Marshal(assertionWire{Signature: []byte{0x30}, RawAuthData: make([]byte, 36)})
		if err != nil {
			t.Fatal(err)
		}

		var assertion appattest.AssertionObject
		err = assertion.UnmarshalBinary(encoded)
		wantError(t, err, "too short")
	})

	t.Run("when the object is not cbor, then it is refused", func(t *testing.T) {
		var assertion appattest.AssertionObject
		if err := assertion.UnmarshalBinary([]byte("not cbor")); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestVerifyAssertion(t *testing.T) {
	challenge := testChallenge()
	clientData := testClientData(challenge)

	t.Run("when the assertion is valid, then the new counter is returned", func(t *testing.T) {
		assertion, publicKey := newAssertion(t, testTeamID, testBundleID, 5, clientData)

		verifier := appattest.NewAssertionVerifier(testTeamID, testBundleID)

		counter, err := verifier.VerifyAssertion(assertion, publicKey, clientData, challenge, 4)
		if err != nil {
			t.Fatal(err)
		}
		if counter != 5 {
			t.Error(counter)
		}
	})

	t.Run("when it is the first assertion, then the counter only has to be above zero", func(t *testing.T) {
		assertion, publicKey := newAssertion(t, testTeamID, testBundleID, 1, clientData)

		verifier := appattest.NewAssertionVerifier(testTeamID, testBundleID)

		counter, err := verifier.VerifyAssertion(assertion, publicKey, clientData, challenge, 0)
		if err != nil {
			t.Fatal(err)
		}
		if counter != 1 {
			t.Error(counter)
		}
	})

	t.Run("when the signature is tampered with, then it is refused", func(t *testing.T) {
		assertion, publicKey := newAssertion(t, testTeamID, testBundleID, 5, clientData)
		assertion.Signature[0] ^= 0xff

		verifier := appattest.NewAssertionVerifier(testTeamID, testBundleID)

		_, err := verifier.VerifyAssertion(assertion, publicKey, clientData, challenge, 4)
		wantError(t, err, "invalid signature")
	})

	t.Run("when the signature belongs to another key, then it is refused", func(t *testing.T) {
		assertion, _ := newAssertion(t, testTeamID, testBundleID, 5, clientData)
		_, otherPublicKey := newAssertion(t, testTeamID, testBundleID, 5, clientData)

		verifier := appattest.NewAssertionVerifier(testTeamID, testBundleID)

		_, err := verifier.VerifyAssertion(assertion, otherPublicKey, clientData, challenge, 4)
		wantError(t, err, "invalid signature")
	})

	t.Run("when the app id differs, then the rp id does not match", func(t *testing.T) {
		assertion, publicKey := newAssertion(t, testTeamID, testBundleID, 5, clientData)

		verifier := appattest.NewAssertionVerifier("WRONGTEAMID", testBundleID)

		_, err := verifier.VerifyAssertion(assertion, publicKey, clientData, challenge, 4)
		wantError(t, err, "unexpected RP ID")
	})

	t.Run("when the counter did not advance, then it is refused", func(t *testing.T) {
		assertion, publicKey := newAssertion(t, testTeamID, testBundleID, 5, clientData)

		verifier := appattest.NewAssertionVerifier(testTeamID, testBundleID)

		_, err := verifier.VerifyAssertion(assertion, publicKey, clientData, challenge, 5)
		wantError(t, err, "counter not incremented")
	})

	// The signature is valid here, so this reaches the challenge check rather than
	// failing earlier on the signature.
	t.Run("when the challenge is absent from the client data, then it is refused", func(t *testing.T) {
		clientDataWithoutChallenge := []byte("a replayed request")
		assertion, publicKey := newAssertion(t, testTeamID, testBundleID, 5, clientDataWithoutChallenge)

		verifier := appattest.NewAssertionVerifier(testTeamID, testBundleID)

		_, err := verifier.VerifyAssertion(assertion, publicKey, clientDataWithoutChallenge, challenge, 4)
		wantError(t, err, "challenge not found in clientData")
	})
}
