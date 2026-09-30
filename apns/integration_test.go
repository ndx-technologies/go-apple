package apns_test

// These tests talk to the real APNs hosts. They are skipped unless a key is
// provided, so the default `go test -short` run stays hermetic:
//
//	APNS_SANDBOX_KEY_PATH=AuthKey_XXXXXXXXXX.p8 \
//	APNS_SANDBOX_KEY_ID=XXXXXXXXXX \
//	APNS_TEAM_ID=ABCDE12345 \
//	APNS_BUNDLE_ID=com.example.app \
//	go test ./apns/ -run Integration -v
//
// An APNs key is created for one environment and is refused by the other, so
// there is a key per environment and the same one cannot serve both. Add
// APNS_PRODUCTION_KEY_PATH and APNS_PRODUCTION_KEY_ID to cover production.
//
// This is the cheapest way to verify the client end to end. Sending to a
// well-formed but unknown token exercises the provider token, the HTTP/2
// connection, the headers, the payload, and the reason parsing; the only thing
// missing is a device, and the answer should be 400 BadDeviceToken.

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ndx-technologies/go-apple/apns"
	"github.com/ndx-technologies/go-apple/applejwt"
)

// integrationBundleID is the apns-topic. It belongs to the app being tested
// rather than to this package, so it is never defaulted here.
func integrationBundleID(t *testing.T) string {
	t.Helper()

	bundleID := os.Getenv("APNS_BUNDLE_ID")
	if bundleID == "" {
		t.Skip("APNS_BUNDLE_ID is required")
	}
	return bundleID
}

func integrationKey(t *testing.T, baseURL string) (name, keyPath, keyID string) {
	t.Helper()

	switch baseURL {
	case apns.ProductionBaseURL:
		return "PRODUCTION", os.Getenv("APNS_PRODUCTION_KEY_PATH"), os.Getenv("APNS_PRODUCTION_KEY_ID")
	case apns.SandboxBaseURL:
		return "SANDBOX", os.Getenv("APNS_SANDBOX_KEY_PATH"), os.Getenv("APNS_SANDBOX_KEY_ID")
	default:
		t.Fatalf("unknown apns host: %s", baseURL)
		return "", "", ""
	}
}

func integrationClient(t *testing.T, baseURL string) apns.APNClient {
	t.Helper()

	name, keyPath, keyID := integrationKey(t, baseURL)
	teamID := os.Getenv("APNS_TEAM_ID")
	bundleID := os.Getenv("APNS_BUNDLE_ID")

	if keyPath == "" || keyID == "" || teamID == "" || bundleID == "" {
		t.Skipf("APNS_%s_KEY_PATH, APNS_%s_KEY_ID, APNS_TEAM_ID and APNS_BUNDLE_ID are required", name, name)
	}

	return integrationClientFromKeyFile(t, baseURL, keyPath, keyID, teamID, bundleID)
}

func integrationClientFromKeyFile(t *testing.T, baseURL, keyPath, keyID, teamID, bundleID string) apns.APNClient {
	t.Helper()

	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("cannot read the key: %s", err)
	}

	issuer, err := applejwt.NewJWTIssuer(applejwt.JWTIssuerConfig{
		IssuerID: teamID,
		KeyID:    keyID,
		TTL:      providerTokenTTL,
	}, pemBytes)
	if err != nil {
		t.Fatalf("cannot make the jwt issuer: %s", err)
	}

	storageConfig := applejwt.JWTStorageConfig{}
	storageConfig = storageConfig.WithDefaults()

	providerToken := applejwt.NewJWTStorage(storageConfig, issuer)

	config := apns.APNClientConfig{
		BaseURL:  baseURL,
		BundleID: bundleID,
	}
	config = config.WithDefaults()

	return apns.APNClient{
		Config:        config,
		ProviderToken: providerToken,
		HTTPClient:    http.DefaultClient,
	}
}

func integrationNotification() testPayload {
	return testPayload{
		APS: apns.APS{
			Alert: &apns.Alert{
				Title: "go-apple",
				Body:  "integration test",
			},
		},
		Data: customEnvelope{Type: "integration_test"},
	}
}

// unknownToken is well formed hex that no device will ever have.
func unknownToken() apns.Token { return apns.Token(strings.Repeat("ab", 32)) }

func TestIntegrationSandboxRejectsUnknownToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := integrationClient(t, apns.SandboxBaseURL)

	resp, err := client.Send(t.Context(), unknownToken(), integrationNotification(), apns.Headers{
		PushType: apns.PushTypeAlert,
	})
	if err != nil {
		t.Fatalf("the request did not complete: %s", err)
	}

	// Anything other than BadDeviceToken means the key, the topic, the token, or
	// the headers are wrong.
	if resp.Status != http.StatusBadRequest {
		t.Errorf("unexpected status: %d %s", resp.Status, resp.Reason)
	}
	if resp.Reason != apns.ReasonBadDeviceToken {
		t.Errorf("unexpected reason: %s", resp.Reason)
	}
	if resp.ID == "" {
		t.Error("APNs did not return an apns-id")
	}
}

func TestIntegrationProductionRejectsUnknownToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := integrationClient(t, apns.ProductionBaseURL)

	resp, err := client.Send(t.Context(), unknownToken(), integrationNotification(), apns.Headers{
		PushType: apns.PushTypeAlert,
	})
	if err != nil {
		t.Fatalf("the request did not complete: %s", err)
	}

	if resp.Status != http.StatusBadRequest {
		t.Errorf("unexpected status: %d %s", resp.Status, resp.Reason)
	}
	if resp.Reason != apns.ReasonBadDeviceToken {
		t.Errorf("unexpected reason: %s", resp.Reason)
	}
}

// Set APNS_DEVICE_TOKEN to a token from a development build to check real
// delivery. This one is expected to be answered with 200, and the banner should
// appear on the device.
func TestIntegrationSandboxDelivers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	deviceToken := os.Getenv("APNS_DEVICE_TOKEN")
	if deviceToken == "" {
		t.Skip("APNS_DEVICE_TOKEN is required")
	}

	client := integrationClient(t, apns.SandboxBaseURL)

	// No expiry, so APNs stores the notification and retries if the device is not
	// reachable this instant. An immediate expiry is discarded instead, which is
	// the wrong trade for a test whose whole point is arriving.
	resp, err := client.Send(t.Context(), apns.Token(deviceToken), integrationNotification(), apns.Headers{
		PushType:   apns.PushTypeAlert,
		Priority:   apns.PriorityImmediate,
		CollapseID: "integration_test",
	})
	if err != nil {
		t.Fatalf("the request did not complete: %s", err)
	}

	t.Logf("accepted as %s: %d %s", resp.ID, resp.Status, resp.Reason)

	if !resp.IsOK() {
		t.Errorf("unexpected status: %d %s", resp.Status, resp.Reason)
	}
}

// A key created for one environment is refused by the other. This is why the
// token's stored environment has to select the host and the key together, and it
// is also the reason a misconfigured key cannot make us delete a good token: the
// refusal is a 403, not the 400 that recycling keys off.
func TestIntegrationSandboxKeyIsRefusedByProduction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	_, keyPath, keyID := integrationKey(t, apns.SandboxBaseURL)
	teamID := os.Getenv("APNS_TEAM_ID")
	if keyPath == "" || keyID == "" || teamID == "" {
		t.Skip("APNS_SANDBOX_KEY_PATH, APNS_SANDBOX_KEY_ID and APNS_TEAM_ID are required")
	}

	client := integrationClientFromKeyFile(t, apns.ProductionBaseURL, keyPath, keyID, teamID, integrationBundleID(t))

	resp, err := client.Send(t.Context(), unknownToken(), integrationNotification(), apns.Headers{
		PushType: apns.PushTypeAlert,
	})
	if err != nil {
		t.Fatalf("the request did not complete: %s", err)
	}

	if resp.IsOK() {
		t.Fatal("production accepted a sandbox key")
	}

	// Worth recording what Apple actually says here, because it decides whether an
	// alert can rely on the reason field at all.
	t.Logf("cross-environment rejection: %d %q", resp.Status, resp.Reason)

	if resp.Status != http.StatusForbidden {
		t.Errorf("unexpected status: %d %s", resp.Status, resp.Reason)
	}
	if !resp.NeedsOperatorAttention() {
		t.Error("a key problem should page someone")
	}
	if resp.TokenIsInvalid() {
		t.Error("a key problem must not be mistaken for a bad device token")
	}
	if _, retryable := resp.Retryable(client.Config); retryable {
		t.Error("retrying a key from the wrong environment cannot help")
	}
}

// Set APNS_UNREGISTERED_KEY_PATH to a valid P-256 key that Apple has never seen to
// check the failure path. It stands in for a revoked key, a typo in the key id, or
// a key generated for the wrong team.
func TestIntegrationUnregisteredKeyIsRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	keyPath := os.Getenv("APNS_UNREGISTERED_KEY_PATH")
	keyID := os.Getenv("APNS_SANDBOX_KEY_ID")
	teamID := os.Getenv("APNS_TEAM_ID")
	if keyPath == "" || keyID == "" || teamID == "" {
		t.Skip("APNS_UNREGISTERED_KEY_PATH, APNS_SANDBOX_KEY_ID and APNS_TEAM_ID are required")
	}

	client := integrationClientFromKeyFile(t, apns.SandboxBaseURL, keyPath, keyID, teamID, integrationBundleID(t))

	resp, err := client.Send(t.Context(), unknownToken(), integrationNotification(), apns.Headers{
		PushType: apns.PushTypeAlert,
	})
	if err != nil {
		t.Fatalf("the request did not complete: %s", err)
	}

	if resp.IsOK() {
		t.Fatal("APNs accepted a key it does not know")
	}
	if resp.Reason != apns.ReasonInvalidProviderToken {
		t.Errorf("unexpected reason: %s %d", resp.Reason, resp.Status)
	}
	if !resp.NeedsOperatorAttention() {
		t.Error("a bad key should page someone")
	}
	if _, retryable := resp.Retryable(client.Config); retryable {
		t.Error("re-signing an unknown key produces the same bad token")
	}
}
