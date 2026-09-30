package appstoreconnect

import "net/http"

// AppStoreConnectClient implements https://developer.apple.com/documentation/appstoreconnectapi
type AppStoreConnectClient struct {
	JWTIssuer interface {
		GetJWT(aud string) (string, error)
	}
	BaseURL string
	Client  *http.Client
}
