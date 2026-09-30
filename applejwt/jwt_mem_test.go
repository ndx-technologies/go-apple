package applejwt_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ndx-technologies/go-apple/applejwt"
)

type mockJWTIssuer struct{ v string }

func (m mockJWTIssuer) GenerateJWT(aud string) (string, time.Time, error) {
	return m.v, time.Now().Add(time.Millisecond * 5), nil
}

// countingJWTIssuer makes re-signing observable: every call returns a new token.
type countingJWTIssuer struct{ n int }

func (m *countingJWTIssuer) GenerateJWT(string) (string, time.Time, error) {
	m.n++
	return strconv.Itoa(m.n), time.Now().Add(time.Hour), nil
}

func TestJWTStorageInvalidate(t *testing.T) {
	issuer := &countingJWTIssuer{}

	config := applejwt.JWTStorageConfig{}
	config = config.WithDefaults()

	s := applejwt.NewJWTStorage(config, issuer)

	t.Run("when called again, then the token is reused", func(t *testing.T) {
		first, err := s.GetJWT("audience")
		if err != nil {
			t.Fatal(err)
		}

		again, err := s.GetJWT("audience")
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Error("token was re-signed")
		}
	})

	t.Run("when invalidated, then a new token is signed", func(t *testing.T) {
		before, err := s.GetJWT("audience")
		if err != nil {
			t.Fatal(err)
		}

		s.Invalidate()

		after, err := s.GetJWT("audience")
		if err != nil {
			t.Fatal(err)
		}
		if after == before {
			t.Error("token was not re-signed")
		}
	})
}

func TestJWTStorage(t *testing.T) {
	issuer := mockJWTIssuer{"mock"}

	config := applejwt.JWTStorageConfig{
		ExpDelay: time.Millisecond * 3,
	}
	s := applejwt.NewJWTStorage(config.WithDefaults(), issuer)

	g, _ := errgroup.WithContext(t.Context())

	for range 10 {
		g.Go(func() error {
			for i := range 100 {
				token, err := s.GetJWT("asdf")
				if err != nil {
					return err
				}
				if token != "mock" {
					return errors.New("unexpected token")
				}
				if i%10 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		t.Error(err)
	}
}
