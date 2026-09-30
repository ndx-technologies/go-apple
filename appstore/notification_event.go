package appstore

import (
	"encoding/json/v2"
	"errors"
	"time"
)

type NotificationEvent struct {
	NotificationType      NotificationType `json:"notification_type"`
	Subtype               Subtype          `json:"subtype,omitzero"`
	Data                  string           `json:"data,omitzero"`
	Summary               string           `json:"summary,omitzero"`
	ExternalPurchaseToken string           `json:"external_purchase_token,omitzero"`
	Version               Version          `json:"version,omitzero"`
	SignedDate            time.Time        `json:"signed_date"`
	NotificationUUID      string           `json:"notification_uuid"`
	Timestamp             time.Time        `json:"ts"`
}

func NotificationEventFromNotification(v ResponseBodyV2DecodedPayload) NotificationEvent {
	data, _ := json.Marshal(v.Data)
	summary, _ := json.Marshal(v.Summary)
	externalPurchaseToken, _ := json.Marshal(v.ExternalPurchaseToken)

	return NotificationEvent{
		NotificationType:      v.NotificationType,
		Subtype:               v.Subtype,
		Data:                  string(data),
		Summary:               string(summary),
		ExternalPurchaseToken: string(externalPurchaseToken),
		Version:               v.Version,
		SignedDate:            time.UnixMilli(v.SignedDate),
		NotificationUUID:      v.NotificationUUID,
		Timestamp:             time.Now(),
	}
}

func (s NotificationEvent) ResponseBodyV2DecodedPayload() (ResponseBodyV2DecodedPayload, error) {
	v := ResponseBodyV2DecodedPayload{
		NotificationType:      s.NotificationType,
		Subtype:               s.Subtype,
		Data:                  new(Data),
		Summary:               new(Summary),
		ExternalPurchaseToken: new(ExternalPurchaseToken),
		Version:               s.Version,
		SignedDate:            s.SignedDate.UnixMilli(),
		NotificationUUID:      s.NotificationUUID,
	}

	if err := errors.Join(
		json.Unmarshal([]byte(s.Data), &v.Data),
		json.Unmarshal([]byte(s.Summary), &v.Summary),
		json.Unmarshal([]byte(s.ExternalPurchaseToken), &v.ExternalPurchaseToken),
	); err != nil {
		return ResponseBodyV2DecodedPayload{}, err
	}

	return v, nil
}
