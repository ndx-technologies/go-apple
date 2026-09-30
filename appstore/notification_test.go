package appstore

import (
	_ "embed"
	"encoding/json/v2"
	"testing"

	"github.com/ndx-technologies/jws"
)

//go:embed testdata/notification_test.json
var notificationTestJSON []byte

func TestResponseBodyV2DecodedPayload_decoding(t *testing.T) {
	var resp responseBodyV2

	if err := json.Unmarshal(notificationTestJSON, &resp); err != nil {
		t.Error(err)
	}

	var jws jws.JWS
	if err := json.Unmarshal(resp.SignedPayload, &jws); err != nil {
		t.Error(err)
	}

	var notification ResponseBodyV2DecodedPayload
	if err := json.Unmarshal(jws.Payload, &notification); err != nil {
		t.Error(err)
	}

	if notification.NotificationType != Test {
		t.Error(notification.NotificationType)
	}
	if notification.NotificationUUID != "445d9ec6-b35a-468a-bcf5-efff4805c27b" {
		t.Error(notification.NotificationUUID)
	}

	if data := notification.Data; data == nil {
		t.Error("data is nil")
	} else {
		if data.Environment != Sandbox {
			t.Error(data.Environment)
		}
		if data.BundleID != "com.meimei168.PriceTracker" {
			t.Error(data.BundleID)
		}
	}

	b, err := json.Marshal(notification)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(b))
}
