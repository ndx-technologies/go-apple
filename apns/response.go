package apns

import (
	"net/http"
	"strconv"
	"time"
)

// Reason is the error code APNs returns alongside a non-200 status.
// https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
type Reason string

const (
	ReasonBadCollapseID               Reason = "BadCollapseId"
	ReasonBadDeviceToken              Reason = "BadDeviceToken"
	ReasonBadExpirationDate           Reason = "BadExpirationDate"
	ReasonBadMessageID                Reason = "BadMessageId"
	ReasonBadPriority                 Reason = "BadPriority"
	ReasonBadTopic                    Reason = "BadTopic"
	ReasonDeviceTokenNotForTopic      Reason = "DeviceTokenNotForTopic"
	ReasonDuplicateHeaders            Reason = "DuplicateHeaders"
	ReasonIdleTimeout                 Reason = "IdleTimeout"
	ReasonInvalidPushType             Reason = "InvalidPushType"
	ReasonMissingDeviceToken          Reason = "MissingDeviceToken"
	ReasonMissingTopic                Reason = "MissingTopic"
	ReasonPayloadEmpty                Reason = "PayloadEmpty"
	ReasonTopicDisallowed             Reason = "TopicDisallowed"
	ReasonBadCertificate              Reason = "BadCertificate"
	ReasonBadCertificateEnvironment   Reason = "BadCertificateEnvironment"
	ReasonExpiredProviderToken        Reason = "ExpiredProviderToken"
	ReasonForbidden                   Reason = "Forbidden"
	ReasonInvalidProviderToken        Reason = "InvalidProviderToken"
	ReasonMissingProviderToken        Reason = "MissingProviderToken"
	ReasonUnrelatedKeyIDInToken       Reason = "UnrelatedKeyIdInToken"
	ReasonBadEnvironmentKeyIDInToken  Reason = "BadEnvironmentKeyInToken" // 2026-09-30 verified against the sandbox: Apple's documentation spells this reason "BadEnvironmentKeyIdInToken" and the wire value differs.
	ReasonBadPath                     Reason = "BadPath"
	ReasonMethodNotAllowed            Reason = "MethodNotAllowed"
	ReasonExpiredToken                Reason = "ExpiredToken"
	ReasonUnregistered                Reason = "Unregistered"
	ReasonPayloadTooLarge             Reason = "PayloadTooLarge"
	ReasonTooManyProviderTokenUpdates Reason = "TooManyProviderTokenUpdates"
	ReasonTooManyRequests             Reason = "TooManyRequests"
	ReasonInternalServerError         Reason = "InternalServerError"
	ReasonServiceUnavailable          Reason = "ServiceUnavailable"
	ReasonShutdown                    Reason = "Shutdown"
)

type ErrResponse struct {
	ID     NotificationID
	Status int
	Reason Reason
}

func (s ErrResponse) Error() string {
	msg := "apns: " + strconv.Itoa(s.Status) + " " + http.StatusText(s.Status)
	if s.Reason != "" {
		msg += ": " + string(s.Reason)
	}
	return msg
}

// TokenIsInvalid reports that the device token should be deleted rather than retried.
// These are the responses Apple says not to repeat.
func (s ErrResponse) TokenIsInvalid() bool {
	switch s.Reason {
	case ReasonBadDeviceToken,
		ReasonDeviceTokenNotForTopic,
		ReasonExpiredToken,
		ReasonUnregistered,
		ReasonMissingDeviceToken:
		return true
	default:
		return false
	}
}

// NeedsProviderTokenRefresh reports that the originator token was rejected and
// should be re-signed. A stale token certainly needs a new one, and one whose
// signature cannot be verified should not be trusted from cache either.
func (s ErrResponse) NeedsProviderTokenRefresh() bool {
	return s.Status == http.StatusForbidden &&
		(s.Reason == ReasonExpiredProviderToken || s.Reason == ReasonInvalidProviderToken)
}

// NeedsOperatorAttention reports a response that no amount of retrying or
// recycling will fix: the provider is misconfigured and the failure is silent
// otherwise, so alert on it.
//
// The test is deliberately fail-safe: every 403 that is not the routine
// stale-token case counts, including a reason we do not recognise or could not
// parse, so a new reason from Apple cannot make a real problem disappear quietly.
func (s ErrResponse) NeedsOperatorAttention() bool {
	if s.Status != http.StatusForbidden {
		return false
	}
	return s.Reason != ReasonExpiredProviderToken
}

// Retryable reports whether the same request may be retried, and how long to
// wait first, taken from the configured delays. A zero delay means retry
// immediately, which is only returned for responses that ask for something to
// change first.
//
// 4xx responses generally mean the request itself is wrong and must be fixed
// rather than repeated.
func (s ErrResponse) Retryable(config APNClientConfig) (after time.Duration, ok bool) {
	switch s.Status {
	case http.StatusInternalServerError, http.StatusServiceUnavailable:
		return config.RetryAfter5xx, true
	case http.StatusTooManyRequests:
		if s.Reason == ReasonTooManyProviderTokenUpdates {
			return config.RetryAfterTokenUpdate, true
		}
		return config.RetryAfterRateLimit, true
	case http.StatusForbidden:
		// A stale token is fixed by re-signing, so one immediate retry is right.
		// An unverifiable signature is not: re-signing produces the same bad
		// token, so retrying only adds 4xx errors, and APNs closes connections
		// that produce them.
		if s.Reason == ReasonExpiredProviderToken {
			return 0, true
		}
	case http.StatusBadRequest:
		if s.Reason == ReasonIdleTimeout {
			return 0, true
		}
	}
	return 0, false
}
