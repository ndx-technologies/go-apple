package appstore_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ndx-technologies/go-apple/appstore"
)

func TestAppStoreClientWithFallback_NoClients(t *testing.T) {
	var s appstore.AppStoreClientWithFallback

	// A fallback with nothing to try must not look like a success: the old
	// behaviour returned a nil result and a nil error together.
	t.Run("when there are no clients, then subscription statuses report an error", func(t *testing.T) {
		status, err := s.GetAllSubscriptionStatuses(t.Context(), appstore.TransactionID("1"))

		if status != nil {
			t.Error(status)
		}
		if !errors.Is(err, appstore.ErrNoClients) {
			t.Error(err)
		}
	})

	t.Run("when there are no clients, then transaction info reports an error", func(t *testing.T) {
		info, err := s.GetTransactionInfo(t.Context(), appstore.TransactionID("1"))

		if info != nil {
			t.Error(info)
		}
		if !errors.Is(err, appstore.ErrNoClients) {
			t.Error(err)
		}
	})

	t.Run("when there are no clients, then consumption reports an error", func(t *testing.T) {
		err := s.SendConsumptionInformation(t.Context(), appstore.TransactionID("1"), appstore.ConsumptionRequest{})

		if !errors.Is(err, appstore.ErrNoClients) {
			t.Error(err)
		}
	})
}

func TestAppStoreClientWithFallback_FallsThrough(t *testing.T) {
	newClient := func(status int, body string) appstore.AppleAppStoreClient {
		return appstore.AppleAppStoreClient{
			JWTProvider: &mockJWTProvider{},
			JWSVerifier: &mockJWSVerifier{},
			HTTPClient: &mockHTTPClient{
				resp: &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))},
			},
		}
	}

	t.Run("when the first client fails, then the next one is used", func(t *testing.T) {
		s := appstore.AppStoreClientWithFallback{Clients: []appstore.AppleAppStoreClient{
			newClient(http.StatusInternalServerError, ""),
			newClient(http.StatusOK, string(transactionInfoJSON)),
		}}

		info, err := s.GetTransactionInfo(t.Context(), appstore.TransactionID("12345"))
		if err != nil {
			t.Fatal(err)
		}
		if info == nil {
			t.Fatal("nil response")
		}
	})

	t.Run("when every client fails, then the error is reported", func(t *testing.T) {
		s := appstore.AppStoreClientWithFallback{Clients: []appstore.AppleAppStoreClient{
			newClient(http.StatusInternalServerError, ""),
			newClient(http.StatusUnauthorized, ""),
		}}

		info, err := s.GetTransactionInfo(t.Context(), appstore.TransactionID("12345"))

		if info != nil {
			t.Error(info)
		}
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestTransactionFromJWSTransactionDecodedPayload_Dates(t *testing.T) {
	// Apple omits fields rather than sending them as null, so an absent date
	// arrives as 0. Mapping that to 1970 made an absent date look like a real
	// one, which defeated callers checking time.Time.IsZero.
	t.Run("when a timestamp is absent, then the date stays zero", func(t *testing.T) {
		tx := appstore.TransactionFromJWSTransactionDecodedPayload(appstore.JWSTransactionDecodedPayload{})

		for name, got := range map[string]time.Time{
			"expires":           tx.ExpiresDate,
			"original purchase": tx.OriginalPurchaseDate,
			"purchase":          tx.PurchaseDate,
			"revocation":        tx.RevocationDate,
			"signed":            tx.SignedDate,
		} {
			if !got.IsZero() {
				t.Errorf("%s: got %s, want the zero time", name, got)
			}
		}
	})

	t.Run("when a timestamp is present, then it is UTC", func(t *testing.T) {
		const ms = int64(1742782162000)

		tx := appstore.TransactionFromJWSTransactionDecodedPayload(appstore.JWSTransactionDecodedPayload{PurchaseDate: ms})

		if want := time.UnixMilli(ms).UTC(); !tx.PurchaseDate.Equal(want) {
			t.Error(tx.PurchaseDate)
		}
		if _, offset := tx.PurchaseDate.Zone(); offset != 0 {
			t.Errorf("expected UTC, got offset %d", offset)
		}
	})
}
