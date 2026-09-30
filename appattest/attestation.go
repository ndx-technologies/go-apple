package appattest

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// AttestationObject is Apple App Attest attestation object.
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
type AttestationObject struct {
	Format       string               `cbor:"fmt"`
	AttStatement AttestationStatement `cbor:"attStmt"`
	RawAuthData  []byte               `cbor:"authData"`
	AuthData     AuthenticatorData    `cbor:"-"`
}

func (s *AttestationObject) UnmarshalBinary(data []byte) error {
	if err := cbor.Unmarshal(data, s); err != nil {
		return err
	}

	if s.Format != "apple-appattest" {
		return errors.New("unexpected fmt")
	}

	return s.AuthData.UnmarshalBinary(s.RawAuthData)
}

type AttestationStatement struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}
