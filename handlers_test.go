package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	return &Server{
		Config:  cfg,
		KeyPair: kp,
		Store:   NewStore(),
	}
}

func TestDiscoveryEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	srv.HandleDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("unexpected issuer: %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "http://localhost:8080/authorize" {
		t.Errorf("unexpected authorization_endpoint: %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "http://localhost:8080/token" {
		t.Errorf("unexpected token_endpoint: %v", doc["token_endpoint"])
	}
	if doc["jwks_uri"] != "http://localhost:8080/jwks" {
		t.Errorf("unexpected jwks_uri: %v", doc["jwks_uri"])
	}
	if doc["userinfo_endpoint"] != "http://localhost:8080/userinfo" {
		t.Errorf("unexpected userinfo_endpoint: %v", doc["userinfo_endpoint"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/jwks", nil)
	w := httptest.NewRecorder()

	srv.HandleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var jwks map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected 1 key, got %v", jwks["keys"])
	}
	key := keys[0].(map[string]any)
	if key["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got %v", key["alg"])
	}
	if key["kid"] != srv.KeyPair.KID {
		t.Errorf("expected kid=%s, got %v", srv.KeyPair.KID, key["kid"])
	}
	if key["use"] != "sig" {
		t.Errorf("expected use=sig, got %v", key["use"])
	}
}
