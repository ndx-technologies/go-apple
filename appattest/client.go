package appattest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var ErrNotFound = errors.New("appattest: receipt not found")

type ClientConfig struct {
	BaseURL string `json:"base_url"`
}

func (s ClientConfig) WithDefaults() ClientConfig {
	if s.BaseURL == "" {
		s.BaseURL = "https://data.appattest.apple.com"
	}
	return s
}

type Client struct {
	Config      ClientConfig
	HTTPClient  *http.Client
	JWTProvider interface {
		GetJWT(aud string) (token string, err error)
	}
}

// GetAttestationData fetches new receipt for device associated with provided receipt.
// 2025-12-22: it is possible to get receipt multiple times for the same ATTEST receipt
// https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk
func (s Client) GetAttestationData(ctx context.Context, receipt []byte) ([]byte, error) {
	reqBody := base64.StdEncoding.EncodeToString(receipt)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.BaseURL+"/v1/attestationData", strings.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	token, err := s.JWTProvider.GetJWT("")
	if err != nil {
		return nil, fmt.Errorf("getting jwt: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	newReceipt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(respBody)))
	if err != nil {
		return nil, fmt.Errorf("decoding response body: %w", err)
	}

	if len(newReceipt) == 0 {
		return nil, fmt.Errorf("empty receipt in response")
	}

	return newReceipt, nil
}
