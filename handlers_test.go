package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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

func TestAuthorizeEndpoint_InvalidClient(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=bad&redirect_uri=http://example.com/cb&response_type=code&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthorizeEndpoint_RendersPicker(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&nonce=abc", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Alice") {
		t.Error("expected Alice in picker")
	}
	if !strings.Contains(body, "Bob") {
		t.Error("expected Bob in picker")
	}
}

func TestAuthorizeCallback_RedirectsWithCode(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("sub=user1&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") == "" {
		t.Error("expected code in redirect")
	}
	if u.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", u.Query().Get("state"))
	}
}

func TestTokenEndpoint_ValidExchange(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("testcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "nonce1",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=testcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", resp["token_type"])
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Error("expected id_token")
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("expected access_token")
	}
}

func TestTokenEndpoint_InvalidClient(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("grant_type=authorization_code&code=x&client_id=bad&client_secret=bad&redirect_uri=http://x")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestTokenEndpoint_CodeAlreadyConsumed(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("once", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	makeReq := func() *httptest.ResponseRecorder {
		form := strings.NewReader("grant_type=authorization_code&code=once&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
		req := httptest.NewRequest("POST", "/token", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.HandleToken(w, req)
		return w
	}

	w1 := makeReq()
	if w1.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", w1.Code)
	}

	w2 := makeReq()
	if w2.Code != http.StatusBadRequest {
		t.Errorf("second exchange: expected 400, got %d", w2.Code)
	}
}
