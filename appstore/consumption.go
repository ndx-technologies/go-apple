package appstore

// ConsumptionRequest is the request body for the Send Consumption Information endpoint.
// https://developer.apple.com/documentation/appstoreserverapi/consumptionrequest
type ConsumptionRequest struct {
	CustomerConsented     bool             `json:"customerConsented"`              // indicates whether the customer consented to provide consumption data.
	ConsumptionPercentage int              `json:"consumptionPercentage,omitzero"` // percentage of the In-App Purchase the customer consumed, in milliunits. Minimum 0, maximum 100000 (100%). For auto-renewable subscriptions with GRANT_PRORATED refund preference, omit this field.
	DeliveryStatus        DeliveryStatus   `json:"deliveryStatus"`
	RefundPreference      RefundPreference `json:"refundPreference,omitzero"`
	SampleContentProvided bool             `json:"sampleContentProvided"` // indicates whether the developer provided, prior to its purchase, a free sample or trial of the content, or information about its functionality.
}

// DeliveryStatus indicates whether the app delivered the In-App Purchase and it works properly.
// https://developer.apple.com/documentation/appstoreserverapi/deliverystatus
type DeliveryStatus string

const (
	DeliveryStatusDelivered               DeliveryStatus = "DELIVERED"
	DeliveryStatusUndeliveredQualityIssue DeliveryStatus = "UNDELIVERED_QUALITY_ISSUE"
	DeliveryStatusUndeliveredWrongItem    DeliveryStatus = "UNDELIVERED_WRONG_ITEM"
	DeliveryStatusUndeliveredServerOutage DeliveryStatus = "UNDELIVERED_SERVER_OUTAGE"
	DeliveryStatusUndeliveredOther        DeliveryStatus = "UNDELIVERED_OTHER"
)

// RefundPreference indicates the developer's preferred outcome for the refund request.
// https://developer.apple.com/documentation/appstoreserverapi/refundpreference
type RefundPreference string

const (
	RefundPreferenceDecline       RefundPreference = "DECLINE"
	RefundPreferenceGrantFull     RefundPreference = "GRANT_FULL"
	RefundPreferenceGrantProrated RefundPreference = "GRANT_PRORATED"
)
