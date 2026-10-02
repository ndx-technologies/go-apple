package apns

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const (
	ProductionBaseURL = "https://api.push.apple.com"
	SandboxBaseURL    = "https://api.sandbox.push.apple.com"
)

type APNClientConfig struct {
	BaseURL               string        `json:"base_url"`
	BundleID              string        `json:"bundle_id"`
	RetryAfter5xx         time.Duration `json:"retry_after_5xx"`
	RetryAfterRateLimit   time.Duration `json:"retry_after_rate_limit"`
	RetryAfterTokenUpdate time.Duration `json:"retry_after_token_update"` // APNs accepts a new provider token at most once every 20 minutes
}

func (s APNClientConfig) WithDefaults() APNClientConfig {
	if s.BaseURL == "" {
		s.BaseURL = ProductionBaseURL
	}
	if s.RetryAfter5xx == 0 {
		s.RetryAfter5xx = time.Minute * 15
	}
	if s.RetryAfterRateLimit == 0 {
		s.RetryAfterRateLimit = time.Minute
	}
	if s.RetryAfterTokenUpdate == 0 {
		s.RetryAfterTokenUpdate = time.Minute * 20
	}
	return s
}

type NotificationID string

func (s NotificationID) IsZero() bool { return s == "" }

func (s NotificationID) String() string { return string(s) }

// CollapseID replaces a notification already on the device with the same id.
type CollapseID string

type NotificationDetails struct {
	ID         NotificationID
	PushType   PushType
	Priority   Priority
	CollapseID CollapseID
	Expiration time.Time // time.Unix(0, 0) means "try once, do not store"
}

type APNClient struct {
	Config        APNClientConfig
	ProviderToken interface {
		GetJWT(aud string) (string, error)
		Invalidate()
	}
	HTTPClient interface {
		Do(req *http.Request) (*http.Response, error)
	}
}

// Token is a device token, the address of one app installation on one device.
// https://developer.apple.com/documentation/usernotifications/registering-your-app-with-apns
type Token string

func (s Token) String() string { return string(s) }

// Send notification to device holding token.
// Payload must be a struct with APS `json:"aps"` field.
func (s APNClient) Send(ctx context.Context, token Token, payload any, details NotificationDetails) error {
	// APNs generates id if missing. however reject immediately if client forget to include it to prevent drift.
	if details.ID.IsZero() {
		return errors.New("missing notification id")
	}

	if details.PushType == "" {
		details.PushType = PushTypeAlert
	}

	if len(details.CollapseID) > MaxCollapseIDSize {
		return ErrCollapseIDTooLong{Size: len(details.CollapseID), Max: MaxCollapseIDSize}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(body) > MaxPayloadSize {
		return ErrPayloadTooLarge{Size: len(body), Max: MaxPayloadSize}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.BaseURL+"/3/device/"+token.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	providerToken, err := s.ProviderToken.GetJWT("")
	if err != nil {
		return err
	}

	req.Header.Set("authorization", "bearer "+providerToken)
	req.Header.Set("apns-topic", s.Config.BundleID)
	req.Header.Set("apns-push-type", string(details.PushType))
	if details.Priority != 0 {
		req.Header.Set("apns-priority", strconv.Itoa(int(details.Priority)))
	}
	if details.ID != "" {
		req.Header.Set("apns-id", string(details.ID))
	}
	if details.CollapseID != "" {
		req.Header.Set("apns-collapse-id", string(details.CollapseID))
	}
	if !details.Expiration.IsZero() {
		req.Header.Set("apns-expiration", strconv.FormatInt(details.Expiration.Unix(), 10))
	}

	httpResp, err := s.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	id := NotificationID(httpResp.Header.Get("apns-id"))
	if id != details.ID {
		return &ErrUnexpectedNotificationID{ID: id, ExpectedID: details.ID}
	}

	if httpResp.StatusCode != http.StatusOK {
		var e struct {
			Reason Reason `json:"reason"`
		}
		if err := json.UnmarshalRead(httpResp.Body, &e); err != nil {
			slog.ErrorContext(ctx, "cannot decode error response", "error", err)
		}

		resp := &ErrResponse{ID: id, Status: httpResp.StatusCode, Reason: e.Reason}

		if resp.NeedsProviderTokenRefresh() {
			s.ProviderToken.Invalidate()
		}

		return resp
	}

	return nil
}

type ErrUnexpectedNotificationID struct{ ID, ExpectedID NotificationID }

func (s *ErrUnexpectedNotificationID) Error() string {
	return "unexpected notification id: " + s.ID.String() + " != " + s.ExpectedID.String() + " (exp)"
}
