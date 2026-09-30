package appstore_test

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ndx-technologies/go-apple/appstore"
	"github.com/ndx-technologies/jws"
	"github.com/ndx-technologies/ocspx"
)

//go:embed testdata/apple_root_cer.pem
var appleRootCertificatesPEM []byte

//go:embed testdata/notification_test.json
var notificationTestJSON []byte

//go:embed testdata/notification_subscription_renewed.json
var notificationSubscriptionRenewedJSON []byte

func TestReceiveNotification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC))) // OCSP responses are valid until June 1, 2024 for valid JWT keys

		appleRootCertificates := x509.NewCertPool()
		if ok := appleRootCertificates.AppendCertsFromPEM(appleRootCertificatesPEM); !ok {
			t.Fatal("bad apple root certificates: pem")
		}

		jwsVerifier := jws.JWSVerifier{Roots: appleRootCertificates}

		tests := []struct {
			requestPayload   []byte
			notificationUUID string
			notificationType appstore.NotificationType
		}{
			{
				requestPayload:   notificationTestJSON,
				notificationUUID: "445d9ec6-b35a-468a-bcf5-efff4805c27b",
				notificationType: appstore.Test,
			},
			{
				requestPayload:   notificationSubscriptionRenewedJSON,
				notificationUUID: "3a73d10c-d4c2-4424-ad25-8e3efc98bbe3",
				notificationType: appstore.DidRenew,
			},
		}

		for _, tc := range tests {
			appleNotificationReceiver := appstore.AppleNotificationReceiverServer{
				JWSVerifier: jwsVerifier,
				NotificationHandler: func(ctx context.Context, notification appstore.ResponseBodyV2DecodedPayload) error {
					if notification.NotificationUUID != tc.notificationUUID {
						t.Error(notification.NotificationUUID)
					}
					if notification.NotificationType != tc.notificationType {
						t.Error(notification.NotificationType)
					}

					e := appstore.NotificationEventFromNotification(notification)
					v, err := e.ResponseBodyV2DecodedPayload()
					if err != nil {
						t.Error(err)
					}
					if notification.NotificationType != v.NotificationType {
						t.Error(notification, v)
					}

					return nil
				},
			}

			ts := httptest.NewServer(http.HandlerFunc(appleNotificationReceiver.ReceiveNotification))
			defer ts.Close()

			res, err := http.Post(ts.URL, "application/json", bytes.NewReader(tc.requestPayload))
			if err != nil {
				t.Error(err)
			}
			if res == nil {
				t.Error("response is nil")
			} else {
				if res.StatusCode != http.StatusOK {
					t.Error(res.StatusCode)
				}
				if err := assertResponseEmpty(res); err != nil {
					t.Error(err)
				}
			}
		}
	})
}

func TestReceiveNotification_OCSP(t *testing.T) {
	if testing.Short() {
		t.Skip("network call to OCSP")
	}

	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Until(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC))) // certificate valid until 2025-10-11

		appleRootCertificates := x509.NewCertPool()
		if ok := appleRootCertificates.AppendCertsFromPEM(appleRootCertificatesPEM); !ok {
			t.Fatal("bad apple root certificates: pem")
		}

		jwsVerifier := jws.JWSVerifier{
			Roots: appleRootCertificates,
			CertOCSPVerifier: ocspx.OCSPClient{
				Config: ocspx.OCSPClientConfig{},
				Client: http.DefaultClient,
			},
		}

		appleNotificationReceiver := appstore.AppleNotificationReceiverServer{
			JWSVerifier: jwsVerifier,
			NotificationHandler: func(ctx context.Context, notification appstore.ResponseBodyV2DecodedPayload) error {
				if notification.NotificationUUID != "445d9ec6-b35a-468a-bcf5-efff4805c27b" {
					t.Error(notification.NotificationUUID)
				}
				if notification.NotificationType != appstore.Test {
					t.Error(notification.NotificationType)
				}
				return nil
			},
		}

		ts := httptest.NewServer(http.HandlerFunc(appleNotificationReceiver.ReceiveNotification))
		defer ts.Close()

		res, err := http.Post(ts.URL, "application/json", bytes.NewReader(notificationTestJSON))
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("response is nil")
		} else {
			if res.StatusCode != http.StatusOK {
				t.Error(res.StatusCode)
			}
			if err := assertResponseEmpty(res); err != nil {
				t.Error(err)
			}
		}
	})
}

func assertResponseEmpty(res *http.Response) error {
	var b bytes.Buffer
	if _, err := b.ReadFrom(res.Body); err != nil {
		return err
	}
	defer res.Body.Close()

	if b.String() != "" {
		return errors.New("got response: " + b.String())
	}

	return nil
}
