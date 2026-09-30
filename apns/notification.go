package apns

// MaxPayloadSize is the APNs limit for an alert notification.
const MaxPayloadSize = 4096

// MaxCollapseIDSize is the apns-collapse-id limit, in bytes.
const MaxCollapseIDSize = 64

// PushType tells APNs what the payload is for.
// It must match the payload: a mismatch can be rejected, delayed, or dropped.
// https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns
type PushType string

const (
	PushTypeAlert      PushType = "alert"      // may be shown to the user
	PushTypeBackground PushType = "background" // delivers silently and requires content-available
)

type Priority int

const (
	PriorityPowerConsiderate Priority = 5
	PriorityImmediate        Priority = 10
)

// InterruptionLevel is how much the notification is allowed to interrupt.
type InterruptionLevel string

const (
	InterruptionLevelPassive       InterruptionLevel = "passive"
	InterruptionLevelActive        InterruptionLevel = "active"
	InterruptionLevelTimeSensitive InterruptionLevel = "time-sensitive" // requires entitlements
	InterruptionLevelCritical      InterruptionLevel = "critical"       // requires entitlements
)

// Alert is the visible part of a notification.
// The text must already be localised: the payload has to be ready to display when it reaches the device.
type Alert struct {
	Title    string `json:"title,omitzero"`
	Subtitle string `json:"subtitle,omitzero"`
	Body     string `json:"body,omitzero"`
}

type NotificationCategory string

// ThreadID groups notifications in Notification Center.
type ThreadID string

type TargetContentID string

// APS is the `aps` dictionary, the only part of the payload whose keys Apple defines.
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
type APS struct {
	Alert             *Alert               `json:"alert,omitzero"`
	Badge             *int                 `json:"badge,omitzero"` // absolute, not a delta: omit to leave it, send 0 to clear it
	Sound             string               `json:"sound,omitzero"` // "default", or a sound file in the app bundle
	ThreadID          ThreadID             `json:"thread-id,omitzero"`
	Category          NotificationCategory `json:"category,omitzero"` // an identifier the app registered with UNUserNotificationCenter
	TargetContentID   TargetContentID      `json:"target-content-id,omitzero"`
	InterruptionLevel InterruptionLevel    `json:"interruption-level,omitzero"`
	MutableContent    bool                 `json:"mutable-content,omitzero"`
	ContentAvailable  bool                 `json:"content-available,omitzero"`
}
