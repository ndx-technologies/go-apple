package appattest_test

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ndx-technologies/go-apple/appattest"
)

type stubJWTProvider struct {
	token string
	err   error
}

func (s stubJWTProvider) GetJWT(string) (string, error) { return s.token, s.err }

// capturedRequest is what the fake Apple received, inspected where it landed so
// the assertions are about what went over the wire.
type capturedRequest struct {
	path          string
	authorization string
	body          string
}

func newClient(t *testing.T, status int, body string) (appattest.Client, *capturedRequest) {
	t.Helper()

	captured := &capturedRequest{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("cannot read the request body: %s", err)
		}

		captured.path = r.URL.Path
		captured.authorization = r.Header.Get("Authorization")
		captured.body = string(b)

		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	config := appattest.ClientConfig{BaseURL: server.URL}

	return appattest.Client{
		Config:      config.WithDefaults(),
		HTTPClient:  http.DefaultClient,
		JWTProvider: stubJWTProvider{token: "test-jwt"},
	}, captured
}

func TestGetAttestationData(t *testing.T) {
	receipt := []byte("attestation receipt")
	freshReceipt := []byte("refreshed receipt")

	t.Run("when Apple answers, then the request shape and the new receipt are correct", func(t *testing.T) {
		client, captured := newClient(t, http.StatusOK, base64.StdEncoding.EncodeToString(freshReceipt))

		got, err := client.GetAttestationData(t.Context(), receipt)
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != string(freshReceipt) {
			t.Error(string(got))
		}
		if captured.path != "/v1/attestationData" {
			t.Error(captured.path)
		}
		// The body is the base64 of the receipt being refreshed, not the raw bytes.
		if want := base64.StdEncoding.EncodeToString(receipt); captured.body != want {
			t.Error(captured.body)
		}
		if captured.authorization != "Bearer test-jwt" {
			t.Error(captured.authorization)
		}
	})

	t.Run("when the response has surrounding whitespace, then it is still parsed", func(t *testing.T) {
		client, _ := newClient(t, http.StatusOK, "\n  "+base64.StdEncoding.EncodeToString(freshReceipt)+"\n")

		got, err := client.GetAttestationData(t.Context(), receipt)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(freshReceipt) {
			t.Error(string(got))
		}
	})

	// Apple answers 404 when it has no record of the receipt, which the caller
	// needs to tell apart from a transport or configuration failure.
	t.Run("when Apple has no record of the receipt, then it is reported as not found", func(t *testing.T) {
		client, _ := newClient(t, http.StatusNotFound, "No Data Found")

		_, err := client.GetAttestationData(t.Context(), receipt)
		if !errors.Is(err, appattest.ErrNotFound) {
			t.Error(err)
		}
	})

	t.Run("when Apple fails, then the status is reported", func(t *testing.T) {
		client, _ := newClient(t, http.StatusInternalServerError, "Server Error")

		_, err := client.GetAttestationData(t.Context(), receipt)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Error(err)
		}
	})

	t.Run("when the response is not base64, then it is refused", func(t *testing.T) {
		client, _ := newClient(t, http.StatusOK, "!!!not base64!!!")

		if _, err := client.GetAttestationData(t.Context(), receipt); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("when the response is empty, then it is refused", func(t *testing.T) {
		client, _ := newClient(t, http.StatusOK, "   ")

		if _, err := client.GetAttestationData(t.Context(), receipt); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("when the token cannot be signed, then it is refused", func(t *testing.T) {
		client, _ := newClient(t, http.StatusOK, base64.StdEncoding.EncodeToString(freshReceipt))
		client.JWTProvider = stubJWTProvider{err: errors.New("cannot sign")}

		if _, err := client.GetAttestationData(t.Context(), receipt); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestClientConfigWithDefaults(t *testing.T) {
	t.Run("when the base url is unset, then production is used", func(t *testing.T) {
		config := appattest.ClientConfig{}

		if got := config.WithDefaults(); got.BaseURL != "https://data.appattest.apple.com" {
			t.Error(got.BaseURL)
		}
	})

	t.Run("when the base url is set, then it is kept", func(t *testing.T) {
		config := appattest.ClientConfig{BaseURL: "http://localhost:8080"}

		if got := config.WithDefaults(); got.BaseURL != "http://localhost:8080" {
			t.Error(got.BaseURL)
		}
	})
}
