package devicecheck

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
	"uuid"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type DeviceCheckHTTPClientConfig struct {
	BaseURL string `json:"base_url"`
}

func (s DeviceCheckHTTPClientConfig) WithDefaults() DeviceCheckHTTPClientConfig {
	if s.BaseURL == "" {
		s.BaseURL = "https://api.devicecheck.apple.com"
	}
	return s
}

// DeviceCheckHTTPClient does privacy-preserving storage of two bits per Apple device and verification.
// https://developer.apple.com/documentation/devicecheck/accessing-and-modifying-per-device-data
type DeviceCheckHTTPClient struct {
	Config      DeviceCheckHTTPClientConfig
	HTTPClient  *http.Client
	JWTProvider interface {
		GetJWT(aud string) (token string, err error)
	}
}

func (s DeviceCheckHTTPClient) initRequest(req *http.Request) error {
	token, err := s.JWTProvider.GetJWT("")
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return nil
}

type transactionID struct{ uuid.UUID }

func newTransactionID() transactionID { return transactionID{uuid.New()} }

type queryTwoBitsRequest struct {
	DeviceToken   string        `json:"device_token"`   // Base 64–encoded representation of encrypted device information
	TransactionID transactionID `json:"transaction_id"` // Unique transaction identifier from the associated server
	Timestamp     int64         `json:"timestamp"`      // UTC timestamp from the associated server, in milliseconds since the Unix epoch
}

type QueryTwoBitsResponse struct {
	Bit0           bool
	Bit1           bool
	LastUpdateTime time.Time // date of last modification with reduced precision (YYYY-MM)
}

type queryTwoBitsResponse struct {
	Bit0           bool   `json:"bit0"`
	Bit1           bool   `json:"bit1"`
	LastUpdateTime string `json:"last_update_time"` // The date of the last modification, in YYYY-MM format
}

func (s *queryTwoBitsResponse) parse() (*QueryTwoBitsResponse, error) {
	if s == nil {
		return nil, nil
	}
	t, err := time.Parse("2006-01", s.LastUpdateTime)
	if err != nil {
		return nil, err
	}
	return &QueryTwoBitsResponse{Bit0: s.Bit0, Bit1: s.Bit1, LastUpdateTime: t}, nil
}

const failedToFindBitState = "Failed to find bit state"

// QueryTwoBits for a device token.
// If device is new and bits are not set returns nil, nil.
func (s DeviceCheckHTTPClient) QueryTwoBits(ctx context.Context, deviceToken string) (resp *QueryTwoBitsResponse, err error) {
	ctx, span := otel.Tracer("devicecheck").Start(ctx, "QueryTwoBits", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	req := queryTwoBitsRequest{
		DeviceToken:   deviceToken,
		TransactionID: newTransactionID(),
		Timestamp:     time.Now().UnixMilli(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.BaseURL+"/v1/query_two_bits", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	if err := s.initRequest(httpReq); err != nil {
		return nil, err
	}

	httpResp, err := s.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, &httpError{Code: httpResp.StatusCode, Body: string(respBody)}
	}

	// Apple returns "Failed to find bit state" (plain text, not JSON) when bits have never been set.
	// This is a valid 200 response indicating a new device — return nil, nil.
	if string(respBody) == failedToFindBitState {
		return nil, nil
	}

	var respInternal queryTwoBitsResponse
	if err := json.Unmarshal(respBody, &respInternal); err != nil {
		slog.ErrorContext(ctx, "devicecheck: cannot unmarshal QueryTwoBits response", "error", err, "body", string(respBody))
		return nil, err
	}

	return respInternal.parse()
}

type updateTwoBitsRequest struct {
	DeviceToken   string        `json:"device_token"`   // Base 64–encoded representation of encrypted device information
	TransactionID transactionID `json:"transaction_id"` // Unique transaction identifier from the associated server
	Timestamp     int64         `json:"timestamp"`      // UTC timestamp from the associated server, in milliseconds since the Unix epoch
	Bit0          *bool         `json:"bit0,omitempty"`
	Bit1          *bool         `json:"bit1,omitempty"`
}

func (s DeviceCheckHTTPClient) UpdateTwoBits(ctx context.Context, deviceToken string, bit0, bit1 *bool) (err error) {
	ctx, span := otel.Tracer("devicecheck").Start(ctx, "UpdateTwoBits", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	req := updateTwoBitsRequest{
		DeviceToken:   deviceToken,
		TransactionID: newTransactionID(),
		Timestamp:     time.Now().UnixMilli(),
		Bit0:          bit0,
		Bit1:          bit1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.BaseURL+"/v1/update_two_bits", bytes.NewReader(body))
	if err != nil {
		return err
	}

	if err := s.initRequest(httpReq); err != nil {
		return err
	}

	resp, err := s.HTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newHTTPErrorFromResponse(resp)
	}

	return nil
}

type validateDeviceTokenRequest struct {
	DeviceToken   string        `json:"device_token"`   // Base 64–encoded representation of encrypted device information
	TransactionID transactionID `json:"transaction_id"` // Unique transaction identifier from the associated server
	Timestamp     int64         `json:"timestamp"`      // UTC timestamp from the associated server, in milliseconds since the Unix epoch
}

// ValidateDeviceToken with Apple
func (s DeviceCheckHTTPClient) ValidateDeviceToken(ctx context.Context, deviceToken string) (err error) {
	ctx, span := otel.Tracer("devicecheck").Start(ctx, "ValidateDeviceToken", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	req := validateDeviceTokenRequest{
		DeviceToken:   deviceToken,
		TransactionID: newTransactionID(),
		Timestamp:     time.Now().UnixMilli(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.BaseURL+"/v1/validate_device_token", bytes.NewReader(body))
	if err != nil {
		return err
	}

	if err := s.initRequest(httpReq); err != nil {
		return err
	}

	resp, err := s.HTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newHTTPErrorFromResponse(resp)
	}

	return nil
}

type httpError struct {
	Code int
	Body string
}

func newHTTPErrorFromResponse(resp *http.Response) *httpError {
	body, _ := io.ReadAll(resp.Body)
	return &httpError{
		Code: resp.StatusCode,
		Body: string(body),
	}
}

func (s *httpError) Error() string {
	return "devicecheck: http error: code:" + strconv.Itoa(s.Code) + " body:" + s.Body
}
