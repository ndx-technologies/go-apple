package apns_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ndx-technologies/go-apple/apns"
)

// These predicates encode the recycling and retry rules from
// https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns

func TestResponseTokenIsInvalid(t *testing.T) {
	t.Run("when the token is gone, then delete it", func(t *testing.T) {
		for _, r := range []apns.ErrResponse{
			{Status: http.StatusGone, Reason: apns.ReasonUnregistered},
			{Status: http.StatusGone, Reason: apns.ReasonExpiredToken},
			{Status: http.StatusBadRequest, Reason: apns.ReasonBadDeviceToken},
			{Status: http.StatusBadRequest, Reason: apns.ReasonDeviceTokenNotForTopic},
			{Status: http.StatusBadRequest, Reason: apns.ReasonMissingDeviceToken},
		} {
			if !r.TokenIsInvalid() {
				t.Errorf("expected an invalid token: %+v", r)
			}
		}
	})

	t.Run("when the request was fine, then keep the token", func(t *testing.T) {
		for _, r := range []apns.ErrResponse{
			{Status: http.StatusOK},
			{Status: http.StatusBadRequest, Reason: apns.ReasonBadTopic},
			{Status: http.StatusBadRequest, Reason: apns.ReasonPayloadEmpty},
			{Status: http.StatusForbidden, Reason: apns.ReasonForbidden},
			{Status: http.StatusServiceUnavailable, Reason: apns.ReasonServiceUnavailable},
			{Status: http.StatusTooManyRequests, Reason: apns.ReasonTooManyRequests},
		} {
			if r.TokenIsInvalid() {
				t.Errorf("expected a valid token: %+v", r)
			}
		}
	})
}

func TestResponseNeedsProviderTokenRefresh(t *testing.T) {
	t.Run("when the originator token is rejected, then refresh", func(t *testing.T) {
		for _, reason := range []apns.Reason{apns.ReasonExpiredProviderToken, apns.ReasonInvalidProviderToken} {
			r := apns.ErrResponse{Status: http.StatusForbidden, Reason: reason}
			if !r.NeedsProviderTokenRefresh() {
				t.Error(reason)
			}
		}
	})

	t.Run("when the token is merely forbidden, then do not refresh", func(t *testing.T) {
		r := apns.ErrResponse{Status: http.StatusForbidden, Reason: apns.ReasonForbidden}
		if r.NeedsProviderTokenRefresh() {
			t.Error(r)
		}
	})

	t.Run("when the status is not forbidden, then do not refresh", func(t *testing.T) {
		r := apns.ErrResponse{Status: http.StatusBadRequest, Reason: apns.ReasonExpiredProviderToken}
		if r.NeedsProviderTokenRefresh() {
			t.Error(r)
		}
	})
}

// Misconfiguration is invisible unless someone is told about it, so these are the
// responses that should page rather than be retried or swallowed.
func TestResponseNeedsOperatorAttention(t *testing.T) {
	t.Run("when the key is not accepted, then a human has to look", func(t *testing.T) {
		for _, reason := range []apns.Reason{
			apns.ReasonInvalidProviderToken,
			apns.ReasonMissingProviderToken,
			apns.ReasonForbidden,
			apns.ReasonBadCertificate,
			apns.ReasonBadCertificateEnvironment,
			apns.ReasonUnrelatedKeyIDInToken,
			apns.ReasonBadEnvironmentKeyIDInToken,
			apns.ReasonBadTopic,
			apns.ReasonMissingTopic,
			apns.ReasonTopicDisallowed,
		} {
			r := apns.ErrResponse{Status: http.StatusForbidden, Reason: reason}
			if !r.NeedsOperatorAttention() {
				t.Error(reason)
			}
		}
	})

	// The rule is fail-safe on purpose: a reason we have never seen, or one we
	// could not parse, must not be able to hide a real problem.
	t.Run("when the reason is unknown or missing, then a human has to look", func(t *testing.T) {
		for _, reason := range []apns.Reason{"", "SomeFutureReason", apns.ReasonBadPriority} {
			r := apns.ErrResponse{Status: http.StatusForbidden, Reason: reason}
			if !r.NeedsOperatorAttention() {
				t.Error(reason)
			}
		}
	})

	t.Run("when the fault is a gone device, then no human is needed", func(t *testing.T) {
		for _, r := range []apns.ErrResponse{
			{Status: http.StatusOK},
			{Status: http.StatusGone, Reason: apns.ReasonUnregistered},
			{Status: http.StatusBadRequest, Reason: apns.ReasonBadDeviceToken},
			{Status: http.StatusServiceUnavailable, Reason: apns.ReasonServiceUnavailable},
			{Status: http.StatusTooManyRequests, Reason: apns.ReasonTooManyRequests},
		} {
			if r.NeedsOperatorAttention() {
				t.Errorf("unexpected attention: %+v", r)
			}
		}
	})

	// A stale token is normal housekeeping and must not page anyone.
	t.Run("when the token needs re-signing, then refresh handles it", func(t *testing.T) {
		r := apns.ErrResponse{Status: http.StatusForbidden, Reason: apns.ReasonExpiredProviderToken}
		if !r.NeedsProviderTokenRefresh() {
			t.Error("expected a refresh")
		}
		if r.NeedsOperatorAttention() {
			t.Error("expected no attention")
		}
	})
}

func TestResponseRetryable(t *testing.T) {
	config := apns.APNClientConfig{}
	config = config.WithDefaults()

	t.Run("when the server failed, then retry after the configured delay", func(t *testing.T) {
		for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
			after, ok := apns.ErrResponse{Status: status}.Retryable(config)
			if !ok {
				t.Errorf("expected retryable: %d", status)
			}
			if after != config.RetryAfter5xx {
				t.Error(after)
			}
		}
	})

	t.Run("when rate limited, then retry after the configured delay", func(t *testing.T) {
		after, ok := apns.ErrResponse{Status: http.StatusTooManyRequests, Reason: apns.ReasonTooManyRequests}.Retryable(config)
		if !ok {
			t.Fatal("expected retryable")
		}
		if after != config.RetryAfterRateLimit {
			t.Error(after)
		}
	})

	t.Run("when the token was updated too often, then wait before updating it again", func(t *testing.T) {
		after, ok := apns.ErrResponse{Status: http.StatusTooManyRequests, Reason: apns.ReasonTooManyProviderTokenUpdates}.Retryable(config)
		if !ok {
			t.Fatal("expected retryable")
		}
		if after != config.RetryAfterTokenUpdate {
			t.Error(after)
		}
	})

	t.Run("when the originator token is stale, then retry immediately after refreshing", func(t *testing.T) {
		after, ok := apns.ErrResponse{Status: http.StatusForbidden, Reason: apns.ReasonExpiredProviderToken}.Retryable(config)
		if !ok {
			t.Fatal("expected retryable")
		}
		if after != 0 {
			t.Error(after)
		}
	})

	// Re-signing a key that Apple does not recognise produces the same bad token,
	// so a retry only adds 4xx errors, which is what makes APNs close connections.
	t.Run("when the signature cannot be verified, then do not retry", func(t *testing.T) {
		if _, ok := (apns.ErrResponse{Status: http.StatusForbidden, Reason: apns.ReasonInvalidProviderToken}).Retryable(config); ok {
			t.Error("expected no retry")
		}
	})

	t.Run("when the device token is dead, then do not retry", func(t *testing.T) {
		for _, r := range []apns.ErrResponse{
			{Status: http.StatusGone, Reason: apns.ReasonUnregistered},
			{Status: http.StatusBadRequest, Reason: apns.ReasonBadDeviceToken},
			{Status: http.StatusBadRequest, Reason: apns.ReasonDeviceTokenNotForTopic},
		} {
			if _, ok := r.Retryable(config); ok {
				t.Errorf("expected no retry: %+v", r)
			}
		}
	})

	t.Run("when the request is wrong, then do not retry", func(t *testing.T) {
		for _, r := range []apns.ErrResponse{
			{Status: http.StatusOK},
			{Status: http.StatusForbidden, Reason: apns.ReasonForbidden},
			{Status: http.StatusRequestEntityTooLarge, Reason: apns.ReasonPayloadTooLarge},
			{Status: http.StatusBadRequest, Reason: apns.ReasonBadPriority},
			{Status: http.StatusNotFound, Reason: apns.ReasonBadPath},
		} {
			if _, ok := r.Retryable(config); ok {
				t.Errorf("expected no retry: %+v", r)
			}
		}
	})
}

func TestErrResponseError(t *testing.T) {
	t.Run("when the reason is known, then both status and reason are in the message", func(t *testing.T) {
		e := apns.ErrResponse{ID: testNotificationID, Status: http.StatusGone, Reason: apns.ReasonUnregistered}
		if msg := e.Error(); !strings.Contains(msg, "410") || !strings.Contains(msg, "Unregistered") {
			t.Error(msg)
		}
	})

	t.Run("when the reason is missing, then the status still stands", func(t *testing.T) {
		e := apns.ErrResponse{Status: http.StatusServiceUnavailable}
		if msg := e.Error(); !strings.Contains(msg, "503") {
			t.Error(msg)
		}
	})
}
