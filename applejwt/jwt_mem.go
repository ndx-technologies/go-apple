package applejwt

import (
	"sync"
	"time"
)

type JWTStorageConfig struct {
	ExpDelay time.Duration `json:"exp_delay"` // issue new token if token expires sooner than this
}

func (s JWTStorageConfig) WithDefaults() JWTStorageConfig {
	if s.ExpDelay == 0 {
		s.ExpDelay = time.Minute
	}
	return s
}

type jwtIssuer interface {
	GenerateJWT(aud string) (string, time.Time, error)
}

type jwtCacheEntry struct {
	token string
	exp   time.Time
}

// JWTStorage is a local thread-safe storage to efficiently reuse tokens.
type JWTStorage struct {
	config JWTStorageConfig
	issuer jwtIssuer
	// state
	tokens map[string]jwtCacheEntry
	mtx    *sync.RWMutex
}

func NewJWTStorage(config JWTStorageConfig, issuer jwtIssuer) *JWTStorage {
	return &JWTStorage{
		config: config,
		issuer: issuer,
		tokens: make(map[string]jwtCacheEntry),
		mtx:    &sync.RWMutex{},
	}
}

func (s *JWTStorage) key(aud string) string { return aud }

func (s *JWTStorage) GetJWT(aud string) (token string, err error) {
	s.mtx.RLock()

	k := s.key(aud)
	if entry, ok := s.tokens[k]; ok && entry.token != "" && time.Until(entry.exp) > s.config.ExpDelay {
		s.mtx.RUnlock()
		return entry.token, nil
	}
	s.mtx.RUnlock()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	token, exp, err := s.issuer.GenerateJWT(aud)
	if err != nil {
		return "", err
	}

	s.tokens[k] = jwtCacheEntry{token: token, exp: exp}

	return token, nil
}

// Invalidate drops every cached token, so the next GetJWT signs a new one.
//
// Call it when the API rejects the token it was given, and retry. Do not call it
// per request: Apple rate limits token updates to roughly one every 20 minutes
// on some of its APIs.
func (s *JWTStorage) Invalidate() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	clear(s.tokens)
}
