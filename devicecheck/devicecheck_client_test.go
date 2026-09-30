package devicecheck_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ndx-technologies/go-apple/devicecheck"
)

type mockJWTProvider struct{}

func (m mockJWTProvider) GetJWT(aud string) (string, error) { return "mock-jwt-token", nil }

func TestDeviceCheckHTTPClient_QueryTwoBits(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		tests := []struct {
			name string
			body string
			resp *devicecheck.QueryTwoBitsResponse
		}{
			{
				name: "new device",
				body: `Failed to find bit state`,
				resp: nil,
			},
			{
				name: "both false",
				body: `{"bit0": false, "bit1": false, "last_update_time": "2024-12"}`,
				resp: &devicecheck.QueryTwoBitsResponse{Bit0: false, Bit1: false, LastUpdateTime: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)},
			},
			{
				name: "bit0 true",
				body: `{"bit0": true, "bit1": false, "last_update_time": "2024-12"}`,
				resp: &devicecheck.QueryTwoBitsResponse{Bit0: true, Bit1: false, LastUpdateTime: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)},
			},
			{
				name: "both true",
				body: `{"bit0": true, "bit1": true, "last_update_time": "2024-12"}`,
				resp: &devicecheck.QueryTwoBitsResponse{Bit0: true, Bit1: true, LastUpdateTime: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(tc.body))
				}))
				defer ts.Close()

				s := devicecheck.DeviceCheckHTTPClient{
					Config:      devicecheck.DeviceCheckHTTPClientConfig{BaseURL: ts.URL},
					HTTPClient:  http.DefaultClient,
					JWTProvider: mockJWTProvider{},
				}

				resp, err := s.QueryTwoBits(t.Context(), "test-device-token")
				if err != nil {
					t.Error(err)
				}
				if tc.resp == nil {
					if resp != nil {
						t.Error(resp)
					}
				} else {
					if resp == nil {
						t.Error("response is nil")
					} else if *resp != *tc.resp {
						t.Error(tc.resp, *resp)
					}
				}
			})
		}
	})

	t.Run("error", func(t *testing.T) {
		tests := []struct {
			statusCode   int
			responseBody string
		}{
			{statusCode: http.StatusUnauthorized, responseBody: "Unauthorized"},
			{statusCode: http.StatusBadRequest, responseBody: "Missing or incorrectly formatted device token"},
			{statusCode: http.StatusInternalServerError, responseBody: "Internal Server Error"},
		}
		for _, tc := range tests {
			t.Run(tc.responseBody, func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.statusCode)
					w.Write([]byte(tc.responseBody))
				}))
				defer ts.Close()

				s := devicecheck.DeviceCheckHTTPClient{
					Config:      devicecheck.DeviceCheckHTTPClientConfig{BaseURL: ts.URL},
					HTTPClient:  http.DefaultClient,
					JWTProvider: mockJWTProvider{},
				}

				if _, err := s.QueryTwoBits(t.Context(), "test-device-token"); err == nil {
					t.Error("expected error")
				}
			})
		}
	})
}

func TestDeviceCheckHTTPClient_ValidateDeviceToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
		defer ts.Close()

		s := devicecheck.DeviceCheckHTTPClient{
			Config:      devicecheck.DeviceCheckHTTPClientConfig{BaseURL: ts.URL},
			HTTPClient:  http.DefaultClient,
			JWTProvider: mockJWTProvider{},
		}

		if err := s.ValidateDeviceToken(t.Context(), "test-device-token"); err != nil {
			t.Error(err)
		}
	})

	t.Run("error", func(t *testing.T) {
		respCodes := []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
		}
		for _, code := range respCodes {
			t.Run(strconv.Itoa(code), func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
				defer ts.Close()

				s := devicecheck.DeviceCheckHTTPClient{
					Config:      devicecheck.DeviceCheckHTTPClientConfig{BaseURL: ts.URL},
					HTTPClient:  http.DefaultClient,
					JWTProvider: mockJWTProvider{},
				}

				if err := s.ValidateDeviceToken(t.Context(), "test-device-token"); err == nil {
					t.Error("expected error")
				}
			})
		}
	})
}

func TestDeviceCheckHTTPClient_UpdateTwoBits(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
		defer ts.Close()

		s := devicecheck.DeviceCheckHTTPClient{
			Config:      devicecheck.DeviceCheckHTTPClientConfig{BaseURL: ts.URL},
			HTTPClient:  http.DefaultClient,
			JWTProvider: mockJWTProvider{},
		}

		bit0, bit1 := true, false
		if err := s.UpdateTwoBits(t.Context(), "test-device-token", &bit0, &bit1); err != nil {
			t.Error(err)
		}
	})

	t.Run("error", func(t *testing.T) {
		respCodes := []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
		}
		for _, code := range respCodes {
			t.Run(strconv.Itoa(code), func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
				defer ts.Close()

				s := devicecheck.DeviceCheckHTTPClient{
					Config:      devicecheck.DeviceCheckHTTPClientConfig{BaseURL: ts.URL},
					HTTPClient:  http.DefaultClient,
					JWTProvider: mockJWTProvider{},
				}

				bit0, bit1 := true, false
				if err := s.UpdateTwoBits(t.Context(), "test-device-token", &bit0, &bit1); err == nil {
					t.Error("expected error")
				}
			})
		}
	})
}
