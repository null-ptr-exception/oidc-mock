package main

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if kp.KID == "" {
		t.Fatal("kid is empty")
	}
}

func TestSignIDToken(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:8080",
			Subject:   "user1",
			Audience:  jwt.ClaimStrings{"my-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce:  "test-nonce",
		Email:  "alice@example.com",
		Name:   "Alice",
		Custom: map[string]any{"roles": []string{"admin"}},
	}

	tokenStr, err := kp.SignIDToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if tokenStr == "" {
		t.Fatal("token is empty")
	}

	// Verify the token can be parsed back with the public key
	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return &kp.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token is not valid")
	}
	mapClaims := parsed.Claims.(jwt.MapClaims)
	if mapClaims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", mapClaims["sub"])
	}
	if mapClaims["nonce"] != "test-nonce" {
		t.Errorf("expected nonce=test-nonce, got %v", mapClaims["nonce"])
	}
	if mapClaims["email"] != "alice@example.com" {
		t.Errorf("expected email, got %v", mapClaims["email"])
	}
	roles, ok := mapClaims["roles"]
	if !ok {
		t.Fatal("expected roles claim")
	}
	roleList, ok := roles.([]any)
	if !ok || len(roleList) == 0 || roleList[0] != "admin" {
		t.Errorf("expected roles=[admin], got %v", roles)
	}
}
