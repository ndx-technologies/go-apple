package appattest

// berToDer converts BER encoded data with indefinite length to DER.
func berToDer(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return ber, nil
	}

	// Check if this looks like it has indefinite length encoding
	// Indefinite length is indicated by length byte 0x80 followed by content and end-of-contents (0x00 0x00)
	result, _, err := convertElement(ber)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func convertElement(data []byte) ([]byte, int, error) {
	if len(data) < 2 {
		return data, len(data), nil
	}

	tag := data[0]
	lenByte := data[1]
	headerLen := 2
	var contentLen int
	var content []byte

	if lenByte == 0x80 {
		// Indefinite length - find end-of-contents marker (0x00 0x00)
		pos := 2
		var contentParts []byte

		for pos < len(data) {
			if pos+1 < len(data) && data[pos] == 0x00 && data[pos+1] == 0x00 {
				// Found end-of-contents
				pos += 2
				break
			}

			// Recursively convert nested element
			elem, consumed, err := convertElement(data[pos:])
			if err != nil {
				return nil, 0, err
			}
			contentParts = append(contentParts, elem...)
			pos += consumed
		}

		content = contentParts

		// Build DER with definite length
		der := buildDerElement(tag, content)
		return der, pos, nil
	}

	// Definite length
	if lenByte < 0x80 {
		contentLen = int(lenByte)
	} else {
		numLenBytes := int(lenByte & 0x7f)
		if len(data) < headerLen+numLenBytes {
			return data, len(data), nil
		}
		for i := range numLenBytes {
			contentLen = (contentLen << 8) | int(data[headerLen+i])
		}
		headerLen += numLenBytes
	}

	if len(data) < headerLen+contentLen {
		return data, len(data), nil
	}

	// For constructed types, recursively process content
	if tag&0x20 != 0 {
		content = data[headerLen : headerLen+contentLen]
		var convertedContent []byte
		pos := 0
		for pos < len(content) {
			elem, consumed, err := convertElement(content[pos:])
			if err != nil {
				return nil, 0, err
			}
			if consumed == 0 {
				break
			}
			convertedContent = append(convertedContent, elem...)
			pos += consumed
		}
		der := buildDerElement(tag, convertedContent)
		return der, headerLen + contentLen, nil
	}

	// Primitive type - return as-is
	totalLen := headerLen + contentLen
	return data[:totalLen], totalLen, nil
}

func buildDerElement(tag byte, content []byte) []byte {
	contentLen := len(content)

	if contentLen < 0x80 {
		result := make([]byte, 2+contentLen)
		result[0] = tag
		result[1] = byte(contentLen)
		copy(result[2:], content)
		return result
	}

	// Calculate number of bytes needed for length
	var lenBytes []byte
	l := contentLen
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}

	result := make([]byte, 2+len(lenBytes)+contentLen)
	result[0] = tag
	result[1] = byte(0x80 | len(lenBytes))
	copy(result[2:], lenBytes)
	copy(result[2+len(lenBytes):], content)
	return result
}
