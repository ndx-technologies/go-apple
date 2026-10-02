package apns_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ndx-technologies/go-apple/apns"
	"github.com/ndx-technologies/go-apple/applejwt"
)

const (
	testToken          = apns.Token("00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0")
	testBundleID       = "com.example.app"
	testNotificationID = apns.NotificationID("2b0b3a1e-8f4c-4d5e-9a71-0c3b6d2e5f18")
	providerTokenTTL   = time.Minute * 50 // Inside APNs' 20 minute to 1 hour window for provider token lifetime.
)

// "Try once, do not store": APNs stores the notification otherwise and may deliver it much later.
var expirationImmediate = time.Unix(0, 0)

// customEnvelope is a caller's own payload next to "aps". The package defines
// only the keys inside APS, so this shape is the caller's to choose.
type customEnvelope struct {
	Type string `json:"type"`
	URI  string `json:"uri,omitzero"`
	ID   string `json:"id"`
}

type testPayload struct {
	apns.APS `json:"aps"`
	Data     customEnvelope `json:"data"`
}

// capturedRequest is what the fake APNs received.
type capturedRequest struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// fakeAPNS stands in for APNs. The request is inspected where it lands, on the
// server, so the assertions are about what actually went over the wire rather
// than about an object handed to a fake transport.
type fakeAPNS struct {
	request capturedRequest
	status  int
	reason  string
	apnsID  string
}

func (s *fakeAPNS) handler(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("cannot read the request body: %s", err)
		}

		s.request = capturedRequest{
			method:  r.Method,
			path:    r.URL.Path,
			headers: r.Header.Clone(),
			body:    body,
		}

		if s.apnsID != "" {
			w.Header().Set("apns-id", s.apnsID)
		} else if id := r.Header.Get("apns-id"); id != "" {
			// A real APNs echoes the apns-id the client sent.
			w.Header().Set("apns-id", id)
		}
		w.WriteHeader(s.status)
		if s.reason != "" {
			fmt.Fprintf(w, `{"reason":%q}`, s.reason)
		}
	}
}

// mockProviderToken is only needed where a real one cannot express the case: a
// signing failure, or observing that the token was invalidated.
type mockProviderToken struct {
	token       string
	err         error
	invalidated int
}

func (m *mockProviderToken) GetJWT(string) (string, error) { return m.token, m.err }

func (m *mockProviderToken) Invalidate() { m.invalidated++ }

// refreshingProvider counts signing and invalidation, so a rejection followed by
// a re-sign and an accepted retry is observable.
type refreshingProvider struct {
	signed      int
	invalidated int
}

func (m *refreshingProvider) GetJWT(string) (string, error) {
	m.signed++
	return fmt.Sprintf("provider-token-%d", m.signed), nil
}

func (m *refreshingProvider) Invalidate() { m.invalidated++ }

// testPrivateKeyPEM builds a real P8 key rather than embedding one, so the test
// exercises the same parsing path as a key downloaded from Apple.
func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// newTestProviderToken is a real provider signing with a generated key, so the
// authorization header is produced by the same code as in production. This is
// the wiring a callsite writes, which is the point: there is nothing for the
// package to provide here.
func newTestProviderToken(t *testing.T) *applejwt.JWTStorage {
	t.Helper()

	pemBytes := testPrivateKeyPEM(t)

	issuer, err := applejwt.NewJWTIssuer(applejwt.JWTIssuerConfig{
		IssuerID: "ABCDE12345",
		KeyID:    "2X9R4HXF34",
		TTL:      providerTokenTTL,
	}, pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	storageConfig := applejwt.JWTStorageConfig{}
	storageConfig = storageConfig.WithDefaults()

	return applejwt.NewJWTStorage(storageConfig, issuer)
}

// newClient points the client at a local server instead of api.push.apple.com.
// The base URL is the injection point, so Client.HTTPClient stays a real client.
func newClient(t *testing.T, server *fakeAPNS) (apns.APNClient, *fakeAPNS) {
	t.Helper()

	httpServer := httptest.NewServer(server.handler(t))
	t.Cleanup(httpServer.Close)

	config := apns.APNClientConfig{
		BaseURL:  httpServer.URL,
		BundleID: testBundleID,
	}
	config = config.WithDefaults()

	client := apns.APNClient{
		Config:        config,
		ProviderToken: newTestProviderToken(t),
		HTTPClient:    http.DefaultClient,
	}

	return client, server
}

func TestClientSendRequestShape(t *testing.T) {
	client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

	err := client.Send(t.Context(), testToken, testPayload{
		APS:  apns.APS{Alert: &apns.Alert{Body: "hi"}},
		Data: customEnvelope{Type: "reminder"},
	}, apns.NotificationDetails{
		ID:         "2b0b3a1e-8f4c-4d5e-9a71-0c3b6d2e5f18",
		PushType:   apns.PushTypeAlert,
		Priority:   apns.PriorityImmediate,
		CollapseID: "reminder",
	})
	if err != nil {
		t.Fatal(err)
	}

	got := server.request

	t.Run("when sending, then it is a POST to the device path", func(t *testing.T) {
		if got.method != http.MethodPost {
			t.Error(got.method)
		}
		if want := "/3/device/" + testToken.String(); got.path != want {
			t.Error(got.path)
		}
	})

	t.Run("when sending, then the required headers are set", func(t *testing.T) {
		for header, want := range map[string]string{
			"Apns-Topic":       testBundleID,
			"Apns-Push-Type":   "alert",
			"Apns-Priority":    "10",
			"Apns-Id":          "2b0b3a1e-8f4c-4d5e-9a71-0c3b6d2e5f18",
			"Apns-Collapse-Id": "reminder",
		} {
			if value := got.headers.Get(header); value != want {
				t.Errorf("%s: got %q, want %q", header, value, want)
			}
		}
	})

	t.Run("when sending, then the authorization header carries a bearer token", func(t *testing.T) {
		authorization := got.headers.Get("Authorization")

		token, ok := strings.CutPrefix(authorization, "bearer ")
		if !ok {
			t.Fatalf("not a bearer token: %q", authorization)
		}
		if parts := strings.Split(token, "."); len(parts) != 3 {
			t.Errorf("not a JWT: %q", token)
		}
	})

	t.Run("when sending, then the payload is the body", func(t *testing.T) {
		if !strings.Contains(string(got.body), `"aps"`) {
			t.Error(string(got.body))
		}
		if !strings.Contains(string(got.body), `"data"`) {
			t.Error(string(got.body))
		}
	})
}

func TestClientSendAccepted(t *testing.T) {
	t.Run("when accepted, then no error", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusOK})

		err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("when APNs echoes the id, then no error", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusOK, apnsID: string(testNotificationID)})

		err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("when APNs echoes a different id, then error", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusOK, apnsID: "eabeae54-14a8-11e5-b60b-1697f925ec7b"})

		var unexpected *apns.ErrUnexpectedNotificationID
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &unexpected) {
			t.Error(err)
		}
	})
}

func TestClientSendDefaults(t *testing.T) {
	t.Run("when push type and priority are unset, then defaults are used", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); err != nil {
			t.Fatal(err)
		}

		if got := server.request.headers.Get("Apns-Push-Type"); got != string(apns.PushTypeAlert) {
			t.Error(got)
		}
		// Priority is left to APNs, which then applies its own default.
		if got := server.request.headers.Get("Apns-Priority"); got != "" {
			t.Error(got)
		}
	})
}

func TestClientSendExpiration(t *testing.T) {
	t.Run("when set, then it is sent in seconds", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

		at := time.Unix(1790000000, 0)
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID, Expiration: at}); err != nil {
			t.Fatal(err)
		}

		if got := server.request.headers.Get("Apns-Expiration"); got != "1790000000" {
			t.Error(got)
		}
	})

	t.Run("when now or never, then zero is sent", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID, Expiration: expirationImmediate}); err != nil {
			t.Fatal(err)
		}

		if got := server.request.headers.Get("Apns-Expiration"); got != "0" {
			t.Error(got)
		}
	})

	t.Run("when unset, then the header is absent", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); err != nil {
			t.Fatal(err)
		}

		if _, ok := server.request.headers["Apns-Expiration"]; ok {
			t.Error("unexpected apns-expiration")
		}
	})
}

func TestClientSendRejections(t *testing.T) {
	// A rejection is an answer, not a transport failure, so it comes back as an
	// ErrResponse carrying APNs' status and reason.
	t.Run("when the device is gone, then the reason is parsed", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusGone, reason: "Unregistered"})

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Status != http.StatusGone {
			t.Error(resp.Status)
		}
		if resp.Reason != apns.ReasonUnregistered {
			t.Error(resp.Reason)
		}
		if !resp.TokenIsInvalid() {
			t.Error("expected the token to be marked invalid")
		}
	})

	t.Run("when rejected, then the rejection is an error", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusBadRequest, reason: "BadDeviceToken"})

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Reason != apns.ReasonBadDeviceToken {
			t.Error(resp.Reason)
		}
	})

	t.Run("when the body is empty, then the status still stands", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusServiceUnavailable})

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Reason != "" {
			t.Error(resp.Reason)
		}
		if _, ok := resp.Retryable(client.Config); !ok {
			t.Error("expected retryable")
		}
	})

	t.Run("when the body is not json, then the status still stands", func(t *testing.T) {
		httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("apns-id", r.Header.Get("apns-id"))
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "not json")
		}))
		t.Cleanup(httpServer.Close)

		config := apns.APNClientConfig{
			BaseURL:  httpServer.URL,
			BundleID: testBundleID,
		}
		config = config.WithDefaults()

		client := apns.APNClient{
			Config:        config,
			ProviderToken: newTestProviderToken(t),
			HTTPClient:    http.DefaultClient,
		}

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Status != http.StatusBadRequest {
			t.Error(resp.Status)
		}
	})

	// The environment mismatch is the reason this exists: Apple's documentation
	// lists a different reason string than the one it actually returns.
	t.Run("when the key does not match the environment, then it is not a bad token", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusForbidden, reason: "BadEnvironmentKeyInToken"})

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Reason != apns.ReasonBadEnvironmentKeyIDInToken {
			t.Error(resp.Reason)
		}
		if resp.TokenIsInvalid() {
			t.Error("a key problem must not be mistaken for a bad device token")
		}
		if !resp.NeedsOperatorAttention() {
			t.Error("a key problem should page someone")
		}
		if _, retryable := resp.Retryable(client.Config); retryable {
			t.Error("retrying a key from the wrong environment cannot help")
		}
	})

	t.Run("when the originator token expired, then it is invalidated", func(t *testing.T) {
		server := &fakeAPNS{status: http.StatusForbidden, reason: "ExpiredProviderToken"}

		httpServer := httptest.NewServer(server.handler(t))
		t.Cleanup(httpServer.Close)

		provider := &mockProviderToken{token: "provider-token"}

		config := apns.APNClientConfig{
			BaseURL:  httpServer.URL,
			BundleID: testBundleID,
		}
		config = config.WithDefaults()

		client := apns.APNClient{
			Config:        config,
			ProviderToken: provider,
			HTTPClient:    http.DefaultClient,
		}

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Reason != apns.ReasonExpiredProviderToken {
			t.Error(resp.Reason)
		}
		if provider.invalidated != 1 {
			t.Error(provider.invalidated)
		}
	})

	// Invalidate drops the cached token, so the caller's next attempt is signed
	// with a fresh one and APNs accepts it. Send itself never retries.
	t.Run("when the originator token expired, then the next attempt is re-signed", func(t *testing.T) {
		attempts := 0
		httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.Header().Set("apns-id", r.Header.Get("apns-id"))
			if attempts == 1 {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"reason":"ExpiredProviderToken"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(httpServer.Close)

		provider := &refreshingProvider{}

		config := apns.APNClientConfig{
			BaseURL:  httpServer.URL,
			BundleID: testBundleID,
		}
		config = config.WithDefaults()

		client := apns.APNClient{
			Config:        config,
			ProviderToken: provider,
			HTTPClient:    http.DefaultClient,
		}

		var resp *apns.ErrResponse
		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &resp) {
			t.Fatal(err)
		}
		if resp.Reason != apns.ReasonExpiredProviderToken {
			t.Error(resp.Reason)
		}
		if provider.invalidated != 1 {
			t.Errorf("token was not invalidated: %d", provider.invalidated)
		}

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); err != nil {
			t.Fatal(err)
		}
		if provider.signed != 2 {
			t.Errorf("token was not re-signed: %d", provider.signed)
		}
	})

	t.Run("when the send succeeded, then the token is not invalidated", func(t *testing.T) {
		server := &fakeAPNS{status: http.StatusOK}

		httpServer := httptest.NewServer(server.handler(t))
		t.Cleanup(httpServer.Close)

		provider := &mockProviderToken{token: "provider-token"}

		config := apns.APNClientConfig{
			BaseURL:  httpServer.URL,
			BundleID: testBundleID,
		}
		config = config.WithDefaults()

		client := apns.APNClient{
			Config:        config,
			ProviderToken: provider,
			HTTPClient:    http.DefaultClient,
		}

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); err != nil {
			t.Fatal(err)
		}
		if provider.invalidated != 0 {
			t.Error(provider.invalidated)
		}
	})
}

func TestClientSendErrors(t *testing.T) {
	t.Run("when the notification id is missing, then error before sending", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{}); err == nil {
			t.Fatal("expected an error")
		}
		if server.request.path != "" {
			t.Error("the request was sent anyway")
		}
	})

	t.Run("when the payload is too large, then error before sending", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})

		payload := testPayload{APS: apns.APS{Alert: &apns.Alert{Body: strings.Repeat("a", apns.MaxPayloadSize)}}}

		var tooLarge apns.ErrPayloadTooLarge
		if err := client.Send(t.Context(), testToken, payload, apns.NotificationDetails{ID: testNotificationID}); !errors.As(err, &tooLarge) {
			t.Error(err)
		}
		if server.request.path != "" {
			t.Error("the request was sent anyway")
		}
	})

	t.Run("when the collapse id is too long, then error", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusOK})

		headers := apns.NotificationDetails{ID: testNotificationID, CollapseID: apns.CollapseID(strings.Repeat("a", apns.MaxCollapseIDSize+1))}

		var tooLong apns.ErrCollapseIDTooLong
		if err := client.Send(t.Context(), testToken, testPayload{}, headers); !errors.As(err, &tooLong) {
			t.Error(err)
		}
	})

	t.Run("when the provider token cannot be made, then error", func(t *testing.T) {
		client, server := newClient(t, &fakeAPNS{status: http.StatusOK})
		client.ProviderToken = &mockProviderToken{err: errors.New("no key")}

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); err == nil {
			t.Fatal("expected an error")
		}
		if server.request.path != "" {
			t.Error("the request was sent anyway")
		}
	})

	// Real transport failure, not a faked one: the server is stopped before the send.
	t.Run("when the host is unreachable, then error", func(t *testing.T) {
		httpServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		httpServer.Close()

		config := apns.APNClientConfig{
			BaseURL:  httpServer.URL,
			BundleID: testBundleID,
		}
		config = config.WithDefaults()

		client := apns.APNClient{
			Config:        config,
			ProviderToken: newTestProviderToken(t),
			HTTPClient:    http.DefaultClient,
		}

		if err := client.Send(t.Context(), testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("when the caller cancels, then error", func(t *testing.T) {
		client, _ := newClient(t, &fakeAPNS{status: http.StatusOK})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := client.Send(ctx, testToken, testPayload{}, apns.NotificationDetails{ID: testNotificationID}); !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
}
