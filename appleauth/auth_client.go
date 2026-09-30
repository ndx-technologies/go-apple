package appleauth

import (
	"context"
	"crypto"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/MicahParks/jwkset"
	"github.com/hashicorp/go-retryablehttp"
)

type HTTPClientRetries struct {
	MaxRetries int `json:"max_retries"`
}

type AppleAuthHTTPClientConfig struct {
	BaseURL string            `json:"base_url"`
	Retries HTTPClientRetries `json:"retries"`
}

func (s AppleAuthHTTPClientConfig) WithDefaults() AppleAuthHTTPClientConfig {
	if s.BaseURL == "" {
		s.BaseURL = "https://appleid.apple.com"
	}
	if s.Retries.MaxRetries == 0 {
		s.Retries.MaxRetries = 3
	}
	return s
}

type AppleAuthHTTPClient struct {
	config       AppleAuthHTTPClientConfig
	jwksetClient jwkset.Storage
	httpClient   *http.Client
	tokenURL     string
}

func NewAppleAuthHTTPClient(config AppleAuthHTTPClientConfig, httpClient *http.Client) (AppleAuthHTTPClient, error) {
	hc := retryablehttp.NewClient()
	hc.HTTPClient = httpClient
	hc.RetryMax = config.Retries.MaxRetries

	s := AppleAuthHTTPClient{
		config:     config,
		httpClient: hc.StandardClient(),
		tokenURL:   config.BaseURL + "/auth/token",
	}

	keysURL := s.config.BaseURL + "/auth/keys"
	jwksetClient, err := jwkset.NewDefaultHTTPClient([]string{keysURL})
	if err != nil {
		return s, err
	}
	s.jwksetClient = jwksetClient

	return s, nil
}

// GetJWTKey from Apple for verification of JWT tokens.
// https://developer.apple.com/documentation/sign_in_with_apple/fetch_apple_s_public_key_for_verifying_token_signature
func (s AppleAuthHTTPClient) GetJWTKey(ctx context.Context, kid string) (publicKey crypto.PublicKey, err error) {
	key, err := s.jwksetClient.KeyRead(ctx, kid)
	if err != nil {
		return nil, err
	}
	return key.Key(), nil
}

type GrantType uint8

const (
	AuthorizationCodeGrantType GrantType = iota
	RefreshTokenGrantType
)

func (t GrantType) String() string { return [...]string{"authorization_code", "refresh_token"}[t] }

func (t GrantType) EncodeValues(key string, v *url.Values) error {
	v.Add(key, t.String())
	return nil
}

type GenerateTokenRequest struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Code         string    `json:"code,omitempty"`
	GrantType    GrantType `json:"grant_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	RedirectURL  string    `json:"redirect_url,omitempty"`
}

// GenerateTokenResponse is the result of validation client token with Apple.
// https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
type GenerateTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	IDToken      string `json:"id_token"`   // user identity information
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

var ErrRateLimit = errors.New("rate limit error")
var ErrUnverified = errors.New("unverified error")

// GenerateToken from user input and validate it.
// https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
func (s AppleAuthHTTPClient) GenerateToken(ctx context.Context, req GenerateTokenRequest) (r *GenerateTokenResponse, err error) {
	q := make(url.Values)

	q.Add("client_id", req.ClientID)
	q.Add("client_secret", req.ClientSecret)
	if req.Code != "" {
		q.Add("code", req.Code)
	}
	q.Add("grant_type", req.GrantType.String())
	if req.RefreshToken != "" {
		q.Add("refresh_token", req.RefreshToken)
	}
	if req.RedirectURL != "" {
		q.Add("redirect_url", req.RedirectURL)
	}

	// TODO: use context
	resp, err := s.httpClient.PostForm(s.tokenURL, q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.ErrorContext(ctx, "apple: auth: cannot generate token", "status_code", resp.StatusCode, "body", string(body))
		// TODO: rate limit error code and adjustment

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitHeader := resp.Header.Get("X-Rate-Limit")
			slog.ErrorContext(ctx, "rate limit error", "status_code", resp.StatusCode, "rate_limit", rateLimitHeader)
			return nil, ErrRateLimit
		}

		if resp.StatusCode == http.StatusBadRequest {
			return nil, ErrUnverified
		}

		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	var respBody GenerateTokenResponse
	if err := json.UnmarshalRead(resp.Body, &respBody); err != nil {
		return nil, err
	}

	return &respBody, nil
}
