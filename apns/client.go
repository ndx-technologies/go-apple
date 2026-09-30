package apns

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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

// CollapseID replaces a notification already on the device with the same id.
type CollapseID string

type Headers struct {
	ID         NotificationID // echoed back by the client on tap; empty, APNs assigns one
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

type reasonBody struct {
	Reason    Reason `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}

// Token is a device token, the address of one app installation on one device.
// https://developer.apple.com/documentation/usernotifications/registering-your-app-with-apns
type Token string

func (s Token) String() string { return string(s) }

// A non-nil error means the request never reached APNs or the response could not
// be read. A nil error with a non-200 Response.Status is a normal outcome: read
// Response.TokenIsInvalid and Response.Retryable to decide what to do with it.
//
// Nothing is retried here, including after APNs rejects the provider token and it
// is invalidated. The next attempt is the caller's to make.
func (s APNClient) Send(ctx context.Context, token Token, payload any, h Headers) (resp *Response, err error) {
	ctx, span := otel.Tracer("apns").Start(ctx, "Send", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	if h.PushType == "" {
		h.PushType = PushTypeAlert
	}
	if len(h.CollapseID) > MaxCollapseIDSize {
		return nil, ErrCollapseIDTooLong{Size: len(h.CollapseID), Max: MaxCollapseIDSize}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge{Size: len(body), Max: MaxPayloadSize}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.BaseURL+"/3/device/"+token.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	providerToken, err := s.ProviderToken.GetJWT("")
	if err != nil {
		return nil, err
	}

	req.Header.Set("authorization", "bearer "+providerToken)
	req.Header.Set("apns-topic", s.Config.BundleID)
	req.Header.Set("apns-push-type", string(h.PushType))
	if h.Priority != 0 {
		req.Header.Set("apns-priority", strconv.Itoa(int(h.Priority)))
	}
	if h.ID != "" {
		req.Header.Set("apns-id", string(h.ID))
	}
	if h.CollapseID != "" {
		req.Header.Set("apns-collapse-id", string(h.CollapseID))
	}
	if !h.Expiration.IsZero() {
		req.Header.Set("apns-expiration", strconv.FormatInt(h.Expiration.Unix(), 10))
	}

	span.SetAttributes(attribute.String("apns.push_type", string(h.PushType)))

	httpResp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	id := NotificationID(httpResp.Header.Get("apns-id"))
	if id == "" {
		id = h.ID
	}

	resp = &Response{ID: id, Status: httpResp.StatusCode}

	if resp.IsOK() {
		return resp, nil
	}

	var e reasonBody
	if json.UnmarshalRead(httpResp.Body, &e) == nil {
		resp.Reason = e.Reason
	}

	span.SetAttributes(
		attribute.Int("http.response.status_code", resp.Status),
		attribute.String("apns.reason", string(resp.Reason)),
	)

	if resp.NeedsProviderTokenRefresh() {
		s.ProviderToken.Invalidate()
	}

	return resp, nil
}
