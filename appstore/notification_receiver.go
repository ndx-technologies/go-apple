package appstore

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"

	"github.com/ndx-technologies/jws"
)

// AppleNotificationReceiverServer accepts requests from apple and passes them to supplied handler.
// https://developer.apple.com/documentation/appstoreservernotifications
type AppleNotificationReceiverServer struct {
	JWSVerifier interface {
		VerifyJWS(ctx context.Context, jws jws.JWS) error
	}
	NotificationHandler func(ctx context.Context, notification ResponseBodyV2DecodedPayload) error
}

// https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2
type responseBodyV2 struct {
	SignedPayload jsontext.Value `json:"signedPayload"`
}

func (s AppleNotificationReceiverServer) ReceiveNotification(w http.ResponseWriter, r *http.Request) {
	var resp responseBodyV2

	if err := json.UnmarshalRead(r.Body, &resp); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	var jws jws.JWS
	if err := json.Unmarshal(resp.SignedPayload, &jws); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if err := s.JWSVerifier.VerifyJWS(r.Context(), jws); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	var notification ResponseBodyV2DecodedPayload
	if err := json.Unmarshal(jws.Payload, &notification); err != nil {
		// response has been validated to be from Apple
		// when we cannot unmarshal request, then it is more likely that we are wrong than apple.
		// mark as internal error to stronger mark request as error.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.NotificationHandler(r.Context(), notification); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
