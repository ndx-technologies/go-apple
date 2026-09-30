package appstore_test

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"net/http"
	"testing"

	"github.com/ndx-technologies/go-apple/appstore"
	"github.com/ndx-technologies/jws"
)

//go:embed testdata/transaction.json
var transactionInfoJSON []byte

type mockJWTProvider struct{}

func (m *mockJWTProvider) GetJWT(aud string) (string, error) { return "mock_token", nil }

type mockJWSVerifier struct{ err error }

func (m *mockJWSVerifier) VerifyJWS(ctx context.Context, jws jws.JWS) error { return m.err }

type mockHTTPClient struct{ resp *http.Response }

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) { return m.resp, nil }

func TestAppleAppStoreClient_GetTransactionInfo(t *testing.T) {
	t.Run("when getting valid transaction info, then ok", func(t *testing.T) {
		s := appstore.AppleAppStoreClient{
			JWTProvider: &mockJWTProvider{},
			JWSVerifier: &mockJWSVerifier{},
			HTTPClient:  &mockHTTPClient{resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(transactionInfoJSON))}},
		}

		tx, err := s.GetTransactionInfo(t.Context(), appstore.TransactionID("12345"))
		if err != nil {
			t.Error(err)
		}
		if tx == nil {
			t.Error("nil response")
		} else {
			if tx.Environment != appstore.Sandbox {
				t.Error(tx.Environment)
			}
			if tx.BundleID != appstore.BundleID("com.meimei168.PriceTracker") {
				t.Error(tx.BundleID)
			}
			if tx.ProductID != "advanced_1M" {
				t.Error(tx.ProductID)
			}
			if tx.TransactionID != appstore.TransactionID("2000000880894236") {
				t.Error(tx.TransactionID)
			}
			if tx.OriginalTransactionID != appstore.TransactionID("2000000880881330") {
				t.Error(tx.OriginalTransactionID)
			}
			if tx.SubscriptionGroupIdentifier != appstore.SubscriptionGroupIdentifier("21654111") {
				t.Error(tx.SubscriptionGroupIdentifier)
			}
			t.Logf("%+v", tx)
		}
	})
}
