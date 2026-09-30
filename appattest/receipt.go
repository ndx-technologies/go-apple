package appattest

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"time"
)

// Receipt is Apple App Attest receipt parsed from PKCS#7 ASN.1 payload.
// https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk
type Receipt struct {
	AppID            string    // Field 2: Team ID + "." + Bundle ID
	AttestedPubKey   []byte    // Field 3: DER-encoded public key
	ClientHash       []byte    // Field 4: SHA256 hash
	Token            []byte    // Field 5: Token bytes
	ReceiptType      string    // Field 6: "ATTEST" or "RECEIPT"
	CreationTime     time.Time // Field 12
	RiskMetric       *int      // Field 17: optional
	NotBefore        time.Time // Field 19
	ExpirationTime   time.Time // Field 21
	RawCertificates  [][]byte  // DER-encoded certificates from PKCS#7
	SignerInfos      []byte    // raw signer info for verification
	ContentInfoBytes []byte    // raw content for signature verification
}

// receiptAttribute is ASN.1 structure for receipt field
type receiptAttribute struct {
	Type    int
	Version int
	Value   asn1.RawValue
}

// contentInfo is PKCS#7 ContentInfo
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedData is PKCS#7 SignedData
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

func (s *Receipt) UnmarshalBinary(data []byte) error {
	// Apple receipts use BER encoding which may have indefinite length.
	// Convert BER to DER before parsing.
	der, err := berToDer(data)
	if err != nil {
		return err
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return err
	}

	if !ci.ContentType.Equal(oidSignedData) {
		return errors.New("not a signed-data content type")
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return err
	}

	s.SignerInfos = sd.SignerInfos.Bytes

	// Extract actual content bytes for signature verification
	// The content is wrapped in OCTET STRING (possibly constructed/nested)
	// We need to unwrap and concatenate if constructed.
	content, err := unwrapOctetString(sd.ContentInfo.Content.Bytes)
	if err != nil {
		return err
	}
	s.ContentInfoBytes = content

	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var cert asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &cert)
		if err != nil {
			break
		}
		s.RawCertificates = append(s.RawCertificates, cert.FullBytes)
	}

	// Parse the SET OF ReceiptAttribute
	// The content is the SET (tag 0x31)
	var payload asn1.RawValue
	if _, err := asn1.Unmarshal(content, &payload); err != nil {
		return err
	}

	for rest := payload.Bytes; len(rest) > 0; {
		var attr receiptAttribute
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return err
		}

		// The Value is an OCTET STRING - use its Bytes directly
		valueBytes := attr.Value.Bytes

		if len(valueBytes) == 0 {
			continue
		}

		switch attr.Type {
		case 2:
			s.AppID = string(valueBytes)
		case 3:
			s.AttestedPubKey = valueBytes
		case 4:
			s.ClientHash = valueBytes
		case 5:
			s.Token = valueBytes
		case 6:
			s.ReceiptType = string(valueBytes)
		case 12:
			s.CreationTime, err = parseTime(valueBytes)
		case 17:
			var v int
			v, err = strconv.Atoi(string(valueBytes))
			if err == nil {
				s.RiskMetric = &v
			}
		case 19:
			s.NotBefore, err = parseTime(valueBytes)
		case 21:
			s.ExpirationTime, err = parseTime(valueBytes)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func parseTime(b []byte) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, string(b)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("cannot parse time")
}

func unwrapOctetString(data []byte) ([]byte, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if !raw.IsCompound {
		return raw.Bytes, nil
	}
	// Constructed OCTET STRING: sequence of OCTET STRINGs
	var result []byte
	rest := raw.Bytes
	for len(rest) > 0 {
		var part asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &part)
		if err != nil {
			return nil, err
		}
		result = append(result, part.Bytes...)
	}
	return result, nil
}
