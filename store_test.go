package main

import (
	"testing"
	"time"
)

func TestStoreAuthCode(t *testing.T) {
	s := NewStore()

	s.SaveAuthCode("code123", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "my-app",
		RedirectURI: "http://localhost:3000/callback",
		Nonce:       "nonce1",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	data, ok := s.ConsumeAuthCode("code123")
	if !ok {
		t.Fatal("expected to find auth code")
	}
	if data.UserSub != "user1" {
		t.Errorf("expected user1, got %s", data.UserSub)
	}

	// Second consume should fail (single-use)
	_, ok = s.ConsumeAuthCode("code123")
	if ok {
		t.Fatal("expected auth code to be consumed")
	}
}

func TestExpiredAuthCode(t *testing.T) {
	s := NewStore()

	s.SaveAuthCode("expired", AuthCodeData{
		UserSub:   "user1",
		ExpiresAt: time.Now().Add(-1 * time.Second),
	})

	_, ok := s.ConsumeAuthCode("expired")
	if ok {
		t.Fatal("expected expired auth code to be rejected")
	}
}

func TestAccessTokenStore(t *testing.T) {
	s := NewStore()

	s.SaveAccessToken("tok123", AccessTokenData{UserSub: "user1", Scope: "openid email profile"})

	data, ok := s.GetAccessToken("tok123")
	if !ok {
		t.Fatal("expected to find access token")
	}
	if data.UserSub != "user1" {
		t.Errorf("expected user1, got %s", data.UserSub)
	}
	if data.Scope != "openid email profile" {
		t.Errorf("expected scope 'openid email profile', got %s", data.Scope)
	}

	_, ok = s.GetAccessToken("nonexistent")
	if ok {
		t.Fatal("expected nonexistent token to fail")
	}
}
