package appstore

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ndx-technologies/jws"
)

type AppleAppStoreClientConfig struct {
	BaseURL string `json:"base_url"`
}

type AppleAppStoreClient struct {
	Config      AppleAppStoreClientConfig
	JWTProvider interface {
		GetJWT(aud string) (token string, err error)
	}
	JWSVerifier interface {
		VerifyJWS(ctx context.Context, jws jws.JWS) error
	}
	HTTPClient interface {
		Do(req *http.Request) (*http.Response, error)
	}
}

// StatusResponse is a response that contains status information for all of a customer’s auto-renewable subscriptions in your app.
// https://developer.apple.com/documentation/appstoreserverapi/statusresponse
type StatusResponse struct {
	Data        []SubscriptionGroupIdentifierItem `json:"data"`
	Environment Environment                       `json:"environment"`
	AppAppleID  AppAppleID                        `json:"appAppleId"`
	BundleID    BundleID                          `json:"bundleId"`
}

type SubscriptionGroupIdentifierItem struct {
	SubscriptionGroupIdentifier SubscriptionGroupIdentifier `json:"subscriptionGroupIdentifier"`
	LastTransactions            []LastTransactionsItem      `json:"lastTransactions"`
}

type LastTransactionsItem struct {
	OriginalTransactionID TransactionID  `json:"originalTransactionId"`
	Status                Status         `json:"status"`
	SignedRenewalInfo     JWSRenewalInfo `json:"signedRenewalInfo,omitzero"`
	SignedTransactionInfo JWSTransaction `json:"signedTransactionInfo,omitzero"`
}

// GetAllSubscriptionStatuses for all of a customer’s auto-renewable subscriptions.
// https://developer.apple.com/documentation/appstoreserverapi/get-v1-subscriptions-_transactionid_
func (s AppleAppStoreClient) GetAllSubscriptionStatuses(ctx context.Context, originalTransactionID TransactionID) (status *StatusResponse, err error) {
	ctx, span := otel.Tracer("appstore").Start(ctx, "GetAllSubscriptionStatuses", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Config.BaseURL+"/inApps/v1/subscriptions/"+originalTransactionID.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cannot make request: %w", err)
	}

	token, err := s.JWTProvider.GetJWT("appstoreconnect-v1")
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response http status: %d", resp.StatusCode)
	}

	var v StatusResponse
	if err := json.UnmarshalRead(resp.Body, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

type signedTransactionInfoResponse struct {
	SignedTransactionInfo JWSTransaction `json:"signedTransactionInfo"`
}

// GetTransactionInfo about a single transaction.
// https://developer.apple.com/documentation/appstoreserverapi/get-v1-transactions-_transactionid_
func (s AppleAppStoreClient) GetTransactionInfo(ctx context.Context, transactionID TransactionID) (info *TransactionInfo, err error) {
	ctx, span := otel.Tracer("appstore").Start(ctx, "GetTransactionInfo", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Config.BaseURL+"/inApps/v1/transactions/"+transactionID.String(), nil)
	if err != nil {
		return nil, err
	}

	token, err := s.JWTProvider.GetJWT("appstoreconnect-v1")
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var signedResponse signedTransactionInfoResponse
	if err := json.Unmarshal(body, &signedResponse); err != nil {
		return nil, err
	}

	var jws jws.JWS
	if err := jws.UnmarshalText([]byte(signedResponse.SignedTransactionInfo)); err != nil {
		return nil, err
	}

	if err := s.JWSVerifier.VerifyJWS(ctx, jws); err != nil {
		return nil, err
	}

	var v JWSTransactionDecodedPayload
	if err := json.Unmarshal(jws.Payload, &v); err != nil {
		return nil, err
	}

	transaction := TransactionFromJWSTransactionDecodedPayload(v)
	return &transaction, nil
}

// SendConsumptionInformation sends consumption information about an In-App Purchase to the App Store.
// https://developer.apple.com/documentation/appstoreserverapi/send-consumption-information
func (s AppleAppStoreClient) SendConsumptionInformation(ctx context.Context, transactionID TransactionID, req ConsumptionRequest) (err error) {
	ctx, span := otel.Tracer("appstore").Start(ctx, "SendConsumptionInformation", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
	}()

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, s.Config.BaseURL+"/inApps/v2/transactions/consumption/"+transactionID.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot make request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	token, err := s.JWTProvider.GetJWT("appstoreconnect-v1")
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.HTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("bad response http status: %d", resp.StatusCode)
	}

	return nil
}
