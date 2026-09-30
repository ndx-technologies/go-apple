package appattest

import (
	"github.com/fxamacker/cbor/v2"
)

// AssertionObject is Apple App Attest assertion for verifying subsequent requests.
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
type AssertionObject struct {
	Signature   []byte            `cbor:"signature"`
	RawAuthData []byte            `cbor:"authenticatorData"`
	AuthData    AuthenticatorData `cbor:"-"`
}

func (s *AssertionObject) UnmarshalBinary(b []byte) error {
	if err := cbor.Unmarshal(b, s); err != nil {
		return err
	}
	return s.AuthData.UnmarshalBinary(s.RawAuthData)
}
