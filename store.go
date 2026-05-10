package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type AuthCodeData struct {
	UserSub     string
	ClientID    string
	RedirectURI string
	Nonce       string
	Scope       string
	ExpiresAt   time.Time
}

type AccessTokenData struct {
	UserSub string
	Scope   string
}

type RefreshTokenData struct {
	UserSub  string
	ClientID string
	Scope    string
}

type Store struct {
	mu            sync.Mutex
	authCodes     map[string]AuthCodeData
	accessTokens  map[string]AccessTokenData
	refreshTokens map[string]RefreshTokenData
}

func NewStore() *Store {
	return &Store{
		authCodes:     make(map[string]AuthCodeData),
		accessTokens:  make(map[string]AccessTokenData),
		refreshTokens: make(map[string]RefreshTokenData),
	}
}

func (s *Store) SaveAuthCode(code string, data AuthCodeData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = data
}

func (s *Store) ConsumeAuthCode(code string) (AuthCodeData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.authCodes[code]
	if !ok || time.Now().After(data.ExpiresAt) {
		delete(s.authCodes, code)
		return AuthCodeData{}, false
	}
	delete(s.authCodes, code)
	return data, true
}

func (s *Store) SaveAccessToken(token string, data AccessTokenData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token] = data
}

func (s *Store) GetAccessToken(token string) (AccessTokenData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.accessTokens[token]
	return data, ok
}

func (s *Store) SaveRefreshToken(token string, data RefreshTokenData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token] = data
}

func (s *Store) GetRefreshToken(token string) (RefreshTokenData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.refreshTokens[token]
	return data, ok
}

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
