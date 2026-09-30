package appstore

import (
	"time"
)

// NotificationType describes the in-app purchase or external purchase event for which the App Store sends the version 2 notification.
// https://developer.apple.com/documentation/appstoreservernotifications/notificationtype
type NotificationType string

const (
	ConsumptionRequestNotification        NotificationType = "CONSUMPTION_REQUEST"
	DidChangeRenewalPref                  NotificationType = "DID_CHANGE_RENEWAL_PREF"
	DidChangeRenewalStatus                NotificationType = "DID_CHANGE_RENEWAL_STATUS"
	DidFailToRenew                        NotificationType = "DID_FAIL_TO_RENEW"
	DidRenew                              NotificationType = "DID_RENEW"
	Expired                               NotificationType = "EXPIRED"
	ExternalPurchaseTokenNotificationType NotificationType = "EXTERNAL_PURCHASE_TOKEN"
	GracePeriodExpired                    NotificationType = "GRACE_PERIOD_EXPIRED"
	OfferRedeemed                         NotificationType = "OFFER_REDEEMED"
	OneTimeCharge                         NotificationType = "ONE_TIME_CHARGE"
	PriceIncrease                         NotificationType = "PRICE_INCREASE"
	Refund                                NotificationType = "REFUND"
	RefundDeclined                        NotificationType = "REFUND_DECLINED"
	RefundReversed                        NotificationType = "REFUND_REVERSED"
	RenewalExtended                       NotificationType = "RENEWAL_EXTENDED"
	RenewalExtension                      NotificationType = "RENEWAL_EXTENSION"
	Revoke                                NotificationType = "REVOKE"
	Subscribed                            NotificationType = "SUBSCRIBED"
	Test                                  NotificationType = "TEST"
	PriceChange                           NotificationType = "PRICE_CHANGE"
)

// Subtype provides details about select notification types in version 2.
type Subtype string

const (
	Accepted             Subtype = "ACCEPTED"
	AutoRenewDisabled    Subtype = "AUTO_RENEW_DISABLED"
	AutoRenewEnabled     Subtype = "AUTO_RENEW_ENABLED"
	BillingRecovery      Subtype = "BILLING_RECOVERY"
	BillingRetry         Subtype = "BILLING_RETRY"
	Downgrade            Subtype = "DOWNGRADE"
	Failure              Subtype = "FAILURE"
	GracePeriod          Subtype = "GRACE_PERIOD"
	InitialBuy           Subtype = "INITIAL_BUY"
	Pending              Subtype = "PENDING"
	PriceIncreaseSubtype Subtype = "PRICE_INCREASE"
	ProductNotForSale    Subtype = "PRODUCT_NOT_FOR_SALE"
	Resubscribe          Subtype = "RESUBSCRIBE"
	SummarySubtype       Subtype = "SUMMARY"
	Upgrade              Subtype = "UPGRADE"
	Unreported           Subtype = "UNREPORTED"
	Voluntary            Subtype = "VOLUNTARY"
)

// https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2decodedpayload
type ResponseBodyV2DecodedPayload struct {
	NotificationType      NotificationType       `json:"notificationType"`
	Subtype               Subtype                `json:"subtype,omitzero"`
	Data                  *Data                  `json:"data,omitzero"`
	Summary               *Summary               `json:"summary,omitzero"`
	ExternalPurchaseToken *ExternalPurchaseToken `json:"externalPurchaseToken,omitzero"`
	Version               Version                `json:"version,omitzero"`
	SignedDate            int64                  `json:"signedDate"` // UNIX milliseconds
	NotificationUUID      string                 `json:"notificationUUID"`
}

// https://developer.apple.com/documentation/appstoreservernotifications/data
type Data struct {
	AppAppleID               AppAppleID                `json:"appAppleId,omitzero"`
	BundleID                 BundleID                  `json:"bundleId,omitzero"`
	BundleVersion            BundleVersion             `json:"bundleVersion,omitzero"`
	ConsumptionRequestReason *ConsumptionRequestReason `json:"consumptionRequestReason,omitzero"`
	Environment              Environment               `json:"environment"`
	SignedRenewalInfo        JWSRenewalInfo            `json:"signedRenewalInfo,omitzero"`
	SignedTransactionInfo    JWSTransaction            `json:"signedTransactionInfo,omitzero"`
	Status                   Status                    `json:"status,omitzero"`
}

// https://developer.apple.com/documentation/appstoreservernotifications/summary
type Summary struct {
	RequestIdentifier      RequestIdentifier       `json:"requestIdentifier"`
	Environment            Environment             `json:"environment"`
	AppAppleID             AppAppleID              `json:"appAppleId,omitzero"`
	BundleID               BundleID                `json:"bundleId,omitzero"`
	ProductID              ProductID               `json:"productId,omitzero"`
	StorefrontCountryCodes []StorefrontCountryCode `json:"storefrontCountryCodes"`
	FailedCount            int                     `json:"failedCount"`
	SucceededCount         int                     `json:"succeededCount"`
}

// https://developer.apple.com/documentation/appstoreservernotifications/externalpurchasetoken
type ExternalPurchaseToken struct {
	ExternalPurchaseID string     `json:"externalPurchaseId"`
	TokenCreationDate  int        `json:"tokenCreationDate"` // UNIX milliseconds
	AppAppleID         AppAppleID `json:"appAppleId,omitzero"`
	BundleID           BundleID   `json:"bundleId,omitzero"`
}

type Environment string

const (
	Production Environment = "Production"
	Sandbox    Environment = "Sandbox"
)

// This type uses the ISO 3166-1 Alpha-3 country code representation.
// https://developer.apple.com/documentation/appstoreservernotifications/storefrontcountrycode
type StorefrontCountryCode string

type AppAppleID int

type BundleID string

type BundleVersion string

type ProductID string

func (s ProductID) String() string { return string(s) }

type RequestIdentifier string

type Version string

// The customer-provided reason for a refund request.
// https://developer.apple.com/documentation/appstoreservernotifications/consumptionrequestreason
type ConsumptionRequestReason string

const (
	UnintendedPurchase      ConsumptionRequestReason = "UNINTENDED_PURCHASE"
	FulfillmentIssue        ConsumptionRequestReason = "FULFILLMENT_ISSUE"
	UnsatisfiedWithPurchase ConsumptionRequestReason = "UNSATISFIED_WITH_PURCHASE"
	Legal                   ConsumptionRequestReason = "LEGAL"
	Other                   ConsumptionRequestReason = "OTHER"
)

// The status of an auto-renewable subscription at the time the App Store signs the notification.
// https://developer.apple.com/documentation/appstoreservernotifications/status
type Status uint8

const (
	Active        Status = 1
	ExpiredStatus Status = 2
	Retry         Status = 3
	Grace         Status = 4
	Revoked       Status = 5
)

type Offer struct {
	DiscountType OfferDiscountType `json:"offerDiscountType"`
	Identifier   OfferIdentifier   `json:"offerIdentifier"`
	Period       OfferPeriod       `json:"offerPeriod"`
	Type         OfferType         `json:"offerType"`
}

// Subscription renewal information signed by the App Store, in JSON Web Signature (JWS) format.
// https://developer.apple.com/documentation/appstoreservernotifications/jwsrenewalinfo
// Note, cannot use json.RawMessage since Go will treat it as base64 encoded data and not []byte
type JWSRenewalInfo string

type JWSRenewalInfoDecodedPayload struct {
	Offer
	AppAccountToken             AppAccountToken     `json:"appAccountToken"`
	AppTransactionID            AppTransactionID    `json:"appTransactionId"`
	AutoRenewProductID          AutoRenewProductID  `json:"autoRenewProductId"`
	AutoRenewStatus             AutoRenewStatus     `json:"autoRenewStatus"`
	Currency                    Currency            `json:"currency"`
	EligibleWinBackOfferIDs     []OfferIdentifier   `json:"eligibleWinBackOfferIds"`
	Environment                 Environment         `json:"environment"`
	ExpirationIntent            ExpirationIntent    `json:"expirationIntent"`
	GracePeriodExpiresDate      int                 `json:"gracePeriodExpiresDate"` // Unix, milliseconds
	IsInBillingRetryPeriod      bool                `json:"isInBillingRetryPeriod"`
	OriginalTransactionID       TransactionID       `json:"originalTransactionId"`
	PriceIncreaseStatus         PriceIncreaseStatus `json:"priceIncreaseStatus"`
	ProductID                   ProductID           `json:"productId"`
	RecentSubscriptionStartDate int                 `json:"recentSubscriptionStartDate"` // Unix, milliseconds
	RenewalDate                 int                 `json:"renewalDate"`                 // UNIX, milliseconds
	RenewalPrice                int                 `json:"renewalPrice"`                // milli-units for a currency
	SignedDate                  int                 `json:"signedDate"`                  // UNIX, milliseconds
}

type AppAccountToken string

func (s AppAccountToken) String() string { return string(s) }

type AppTransactionID string

type AutoRenewProductID string

type AutoRenewStatus uint8

const (
	AutoRenewStatusOff AutoRenewStatus = 0
	AutoRenewStatusOn  AutoRenewStatus = 1
)

type ExpirationIntent uint8

const (
	Cancel                       ExpirationIntent = 1
	BillingError                 ExpirationIntent = 2
	NoConsentAutoRenew           ExpirationIntent = 3
	ProductNotAvailableAtRenewal ExpirationIntent = 4
	OtherExpirationIntentReason  ExpirationIntent = 5
)

type OfferDiscountType string

const (
	FreeTrial  OfferDiscountType = "FREE_TRIAL"
	PayAsYouGo OfferDiscountType = "PAY_AS_YOU_GO"
	PayUpFront OfferDiscountType = "PAY_UP_FRONT"
)

// The duration of the offer.
// This field is in ISO 8601 duration format.
// https://developer.apple.com/documentation/appstoreservernotifications/offerperiod
type OfferPeriod string

const (
	// example values
	OfferPeriod1Month  OfferPeriod = "P1M"
	OfferPeriod2Months OfferPeriod = "P2M"
	OfferPeriod3Days   OfferPeriod = "P3D"
)

type OfferType uint8

const (
	IntroductoryOffer OfferType = 1
	PromotionalOffer  OfferType = 2
	SubscriptionOffer OfferType = 3
	WinBackOffer      OfferType = 4
)

// https://developer.apple.com/documentation/appstoreservernotifications/priceincreasestatus
type PriceIncreaseStatus uint8

const (
	NotResponded PriceIncreaseStatus = 0
	Ok           PriceIncreaseStatus = 1
)

// The currency property contains an ISO 4217 alpha-3 string that represents the currency of the price of the product.
// https://developer.apple.com/documentation/appstoreservernotifications/currency
type Currency string

// The string identifier of a subscription offer that you create in App Store Connect.
// https://developer.apple.com/documentation/appstoreservernotifications/offeridentifier
type OfferIdentifier string

// Transaction information signed by the App Store, in JSON Web Signature (JWS) Compact Serialization format.
// https://developer.apple.com/documentation/appstoreservernotifications/jwstransaction
// Note, cannot use json.RawMessage since Go will treat it as base64 encoded data and not []byte
type JWSTransaction string

// https://developer.apple.com/documentation/appstoreservernotifications/jwstransactiondecodedpayload
type JWSTransactionDecodedPayload struct {
	Offer
	AppAccountToken             AppAccountToken             `json:"appAccountToken"`
	AppTransactionID            AppTransactionID            `json:"appTransactionId"`
	BundleID                    BundleID                    `json:"bundleId,omitzero"`
	Currency                    Currency                    `json:"currency"`
	Environment                 Environment                 `json:"environment"`
	ExpiresDate                 int64                       `json:"expiresDate"` // UNIX, milliseconds
	InAppOwnershipType          InAppOwnershipType          `json:"inAppOwnershipType"`
	IsUpgraded                  bool                        `json:"isUpgraded"`
	OriginalPurchaseDate        int64                       `json:"originalPurchaseDate"` // UNIX, milliseconds
	OriginalTransactionID       TransactionID               `json:"originalTransactionId"`
	Price                       int                         `json:"price"` // milli-units for a currency
	ProductID                   ProductID                   `json:"productId"`
	PurchaseDate                int64                       `json:"purchaseDate"` // UNIX, milliseconds
	Quantity                    int                         `json:"quantity"`
	RevocationDate              int64                       `json:"revocationDate"` // UNIX, milliseconds
	RevocationReason            RevocationReason            `json:"revocationReason"`
	SignedDate                  int64                       `json:"signedDate"` // UNIX, milliseconds
	Storefront                  StorefrontCountryCode       `json:"storefront"`
	StorefrontID                StorefrontID                `json:"storefrontId"`
	SubscriptionGroupIdentifier SubscriptionGroupIdentifier `json:"subscriptionGroupIdentifier"`
	TransactionID               TransactionID               `json:"transactionId"`
	TransactionReason           TransactionReason           `json:"transactionReason"`
	Type                        Type                        `json:"type"`
	WebOrderLineItemID          WebOrderLineItemID          `json:"webOrderLineItemId"`
}

type TransactionInfo struct {
	Offer
	AppAccountToken             AppAccountToken             `json:"appAccountToken"`
	AppTransactionID            AppTransactionID            `json:"appTransactionId"`
	BundleID                    BundleID                    `json:"bundleId,omitzero"`
	Currency                    Currency                    `json:"currency"`
	Environment                 Environment                 `json:"environment"`
	ExpiresDate                 time.Time                   `json:"expiresDate"`
	InAppOwnershipType          InAppOwnershipType          `json:"inAppOwnershipType"`
	IsUpgraded                  bool                        `json:"isUpgraded"`
	OriginalPurchaseDate        time.Time                   `json:"originalPurchaseDate"`
	OriginalTransactionID       TransactionID               `json:"originalTransactionId"`
	Price                       int                         `json:"price"` // milli-units for a currency
	ProductID                   ProductID                   `json:"productId"`
	PurchaseDate                time.Time                   `json:"purchaseDate"`
	Quantity                    int                         `json:"quantity"`
	RevocationDate              time.Time                   `json:"revocationDate"`
	RevocationReason            RevocationReason            `json:"revocationReason"`
	SignedDate                  time.Time                   `json:"signedDate"`
	Storefront                  StorefrontCountryCode       `json:"storefront"`
	StorefrontID                StorefrontID                `json:"storefrontId"`
	SubscriptionGroupIdentifier SubscriptionGroupIdentifier `json:"subscriptionGroupIdentifier"`
	TransactionID               TransactionID               `json:"transactionId"`
	TransactionReason           TransactionReason           `json:"transactionReason"`
	Type                        Type                        `json:"type"`
	WebOrderLineItemID          WebOrderLineItemID          `json:"webOrderLineItemId"`
}

// unixMilli reads an Apple timestamp, which is Unix milliseconds in UTC.
// time.UnixMilli would attach the local zone otherwise, and an absent field (0)
// would become 1970 rather than the zero time, which reads as a real date.
func unixMilli(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func TransactionFromJWSTransactionDecodedPayload(v JWSTransactionDecodedPayload) TransactionInfo {
	return TransactionInfo{
		AppAccountToken:             v.AppAccountToken,
		AppTransactionID:            v.AppTransactionID,
		BundleID:                    v.BundleID,
		Currency:                    v.Currency,
		Environment:                 v.Environment,
		ExpiresDate:                 unixMilli(v.ExpiresDate),
		InAppOwnershipType:          v.InAppOwnershipType,
		IsUpgraded:                  v.IsUpgraded,
		OriginalPurchaseDate:        unixMilli(v.OriginalPurchaseDate),
		OriginalTransactionID:       v.OriginalTransactionID,
		Price:                       v.Price,
		ProductID:                   v.ProductID,
		PurchaseDate:                unixMilli(v.PurchaseDate),
		Quantity:                    v.Quantity,
		RevocationDate:              unixMilli(v.RevocationDate),
		RevocationReason:            v.RevocationReason,
		SignedDate:                  unixMilli(v.SignedDate),
		Storefront:                  v.Storefront,
		StorefrontID:                v.StorefrontID,
		SubscriptionGroupIdentifier: v.SubscriptionGroupIdentifier,
		TransactionID:               v.TransactionID,
		TransactionReason:           v.TransactionReason,
		Type:                        v.Type,
		WebOrderLineItemID:          v.WebOrderLineItemID,
	}
}

type InAppOwnershipType string

const (
	FamilyShared InAppOwnershipType = "FAMILY_SHARED"
	Purchased    InAppOwnershipType = "PURCHASED"
)

type RevocationReason uint8

const (
	OtherRevocationReason RevocationReason = 1 // e.g. accidental purchase
	ActualPerceivedReason RevocationReason = 2 // actual perceived issue with an app
)

type StorefrontID string

// SubscriptionGroupIdentifier is the identifier of the subscription group that the subscription belongs to.
// https://developer.apple.com/documentation/appstoreserverapi/subscriptiongroupidentifier
type SubscriptionGroupIdentifier string

type TransactionID string

func (s TransactionID) String() string { return string(s) }

func (s TransactionID) IsZero() bool { return s == "" }

// https://developer.apple.com/documentation/appstoreservernotifications/transactionreason
type TransactionReason string

const (
	Purchase TransactionReason = "PURCHASE"
	Renewal  TransactionReason = "RENEWAL"
)

// The product type of the In-App Purchase.
// https://developer.apple.com/documentation/appstoreservernotifications/type
type Type string

const (
	AutoRenewableSubscription Type = "Auto-Renewable Subscription"
	NonConsumable             Type = "Non-Consumable"
	Consumable                Type = "Consumable"
	NonRenewingSubscription   Type = "Non-Renewing Subscription"
)

type WebOrderLineItemID string
