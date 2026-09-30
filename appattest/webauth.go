package appattest

import (
	"encoding/binary"
	"errors"
)

type AAGUID [16]byte

type WebAuthFlags byte

func (s WebAuthFlags) IsAttestedCredentialDataPresent() bool { return (s & 0x40) != 0 }

// AuthenticatorData from WebAuthn specification with Apple App Attest specifics.
// https://www.w3.org/TR/webauthn/#sctn-authenticator-data
type AuthenticatorData struct {
	RPIDHash     [32]byte // SHA256
	Flags        WebAuthFlags
	Counter      uint32
	AAGUID       AAGUID
	CredentialID []byte // SHA256 of public key (32 bytes)
}

func (s *AuthenticatorData) UnmarshalBinary(b []byte) error {
	if len(b) < 37 {
		return errors.New("too short")
	}

	copy(s.RPIDHash[:], b[0:32])
	s.Flags = WebAuthFlags(b[32])
	s.Counter = binary.BigEndian.Uint32(b[33 : 33+4])

	if s.Flags.IsAttestedCredentialDataPresent() && len(b) >= 32+1+4+16+2 {
		copy(s.AAGUID[:], b[37:53])

		credIDLen := binary.BigEndian.Uint16(b[53 : 53+2])
		if len(b) >= 55+int(credIDLen) {
			s.CredentialID = b[55 : 55+credIDLen]
		}
	}

	return nil
}
