package applejwt

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTIssuerConfig struct {
	IssuerID string        `json:"issuer_id"`        // Issuer ID from the Keys page in App Store Connect (e.g. 57246542-96fe-1a63e053-0824d011072a). https://appstoreconnect.apple.com/access/integrations/api/subs
	BundleID string        `json:"bundle_id"`        // (e.g. com.example.testbundleid) https://developer.apple.com/account/resources/certificates/list
	Subject  string        `json:"subject,omitzero"` // Subject for Sign in with Apple client secret (e.g. com.example.app). https://developer.apple.com/documentation/AccountOrganizationalDataSharing/creating-a-client-secret
	KeyID    string        `json:"key_id"`           // Private key ID from App Store Connect (e.g. 2X9R4HXF34)
	TTL      time.Duration `json:"ttl"`              // max 1h for App Store Connect, up to 6mo for Sign in with Apple
}

func (s JWTIssuerConfig) WithDefaults() JWTIssuerConfig {
	if s.TTL == 0 {
		s.TTL = time.Minute * 5
	}
	return s
}

func (s JWTIssuerConfig) Validate() error {
	if s.IssuerID == "" || s.KeyID == "" {
		return errors.New("missing required fields: issuer_id, key_id")
	}
	return nil
}

type JWTIssuer struct {
	config     JWTIssuerConfig
	privateKey any
}

func NewJWTIssuer(config JWTIssuerConfig, privateKeyP8PEM []byte) (JWTIssuer, error) {
	var block *pem.Block
	if block, _ = pem.Decode(privateKeyP8PEM); block == nil {
		return JWTIssuer{}, errors.New("bad private key: cannot decode pem")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return JWTIssuer{}, fmt.Errorf("bad private key: cannot parse PKCS8: %w", err)
	}

	return JWTIssuer{
		config:     config,
		privateKey: privateKey,
	}, nil
}

// GenerateJWT for Apple API requests.
// Different APIs may require different information passed in claims.
// Example: [App Store Server API], [DeviceCheck].
//
// [App Store Server API]: https://developer.apple.com/documentation/appstoreserverapi/generating-json-web-tokens-for-api-requests
// [DeviceCheck]: https://developer.apple.com/documentation/devicecheck/accessing-and-modifying-per-device-data
func (s JWTIssuer) GenerateJWT(aud string) (string, time.Time, error) {
	issuedAt := time.Now()
	expireAt := issuedAt.Add(s.config.TTL)

	claims := jwt.MapClaims{
		"iss": s.config.IssuerID,
		"iat": issuedAt.Unix(),
		"exp": expireAt.Unix(),
		"aud": aud,
	}

	if s.config.BundleID != "" {
		claims["bid"] = s.config.BundleID
	}

	if s.config.Subject != "" {
		claims["sub"] = s.config.Subject
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.config.KeyID

	tokenStr, err := token.SignedString(s.privateKey)
	if tokenStr == "" {
		err = fmt.Errorf("empty token: %w", err)
	}
	return tokenStr, expireAt, err
}
