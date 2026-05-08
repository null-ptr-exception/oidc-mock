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
	ExpiresAt   time.Time
}

type Store struct {
	mu           sync.Mutex
	authCodes    map[string]AuthCodeData
	accessTokens map[string]string // token -> user sub
}

func NewStore() *Store {
	return &Store{
		authCodes:    make(map[string]AuthCodeData),
		accessTokens: make(map[string]string),
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

func (s *Store) SaveAccessToken(token string, userSub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token] = userSub
}

func (s *Store) GetUserByAccessToken(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.accessTokens[token]
	return sub, ok
}

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
