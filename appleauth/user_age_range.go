package appleauth

// UserAgeRange is ASUserAgeRange
// https://developer.apple.com/documentation/authenticationservices/asuseragerange
type UserAgeRange uint8

//go:generate go-enum-encoding -type=UserAgeRange -string
const (
	EmptyAppleAgeRange   UserAgeRange = iota // json:""
	UnknownAppleAgeRange                     // json:"unknown"
	Child                                    // json:"child"
	NotChild                                 // json:"not_child"
)
