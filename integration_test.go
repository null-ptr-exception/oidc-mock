package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestFullAuthCodeFlow(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	srv := &Server{
		Config:  cfg,
		KeyPair: kp,
		Store:   NewStore(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", srv.HandleDiscovery)
	mux.HandleFunc("GET /authorize", srv.HandleAuthorize)
	mux.HandleFunc("POST /authorize/callback", srv.HandleAuthorizeCallback)
	mux.HandleFunc("POST /token", srv.HandleToken)
	mux.HandleFunc("GET /jwks", srv.HandleJWKS)
	mux.HandleFunc("GET /userinfo", srv.HandleUserinfo)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Update issuer to match test server URL
	srv.Config.Issuer = ts.URL
	srv.Config.Clients[0].RedirectURIs = []string{ts.URL + "/callback"}

	// Step 1: Hit /authorize — should get 200 with picker HTML
	authURL := ts.URL + "/authorize?client_id=default&redirect_uri=" + url.QueryEscape(ts.URL+"/callback") + "&response_type=code&scope=openid&state=teststate&nonce=testnonce"
	resp, err := http.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Step 2: POST /authorize/callback to select a user
	formData := url.Values{
		"sub":          {"user1"},
		"client_id":    {"default"},
		"redirect_uri": {ts.URL + "/callback"},
		"state":        {"teststate"},
		"nonce":        {"testnonce"},
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = client.PostForm(ts.URL+"/authorize/callback", formData)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code in redirect")
	}
	if loc.Query().Get("state") != "teststate" {
		t.Fatalf("expected state=teststate, got %s", loc.Query().Get("state"))
	}

	// Step 3: POST /token to exchange code
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"default"},
		"client_secret": {"secret"},
		"redirect_uri":  {ts.URL + "/callback"},
	}
	resp, err = http.PostForm(ts.URL+"/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	resp.Body.Close()

	idTokenStr, ok := tokenResp["id_token"].(string)
	if !ok || idTokenStr == "" {
		t.Fatal("expected id_token in response")
	}
	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("expected access_token in response")
	}

	// Step 4: Verify the ID token
	parsed, err := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &kp.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse id_token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	if claims["nonce"] != "testnonce" {
		t.Errorf("expected nonce=testnonce, got %v", claims["nonce"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %v", claims["email"])
	}

	// Step 5: GET /userinfo with access token
	req, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d", resp.StatusCode)
	}
	var userInfo map[string]any
	json.NewDecoder(resp.Body).Decode(&userInfo)
	resp.Body.Close()

	if userInfo["sub"] != "user1" {
		t.Errorf("userinfo sub: expected user1, got %v", userInfo["sub"])
	}
	if userInfo["email"] != "alice@example.com" {
		t.Errorf("userinfo email: expected alice@example.com, got %v", userInfo["email"])
	}

	// Step 6: Use refresh token to get new tokens
	refreshToken, ok := tokenResp["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatal("expected refresh_token in token response")
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"default"},
		"client_secret": {"secret"},
	}
	resp, err = http.PostForm(ts.URL+"/token", refreshForm)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d", resp.StatusCode)
	}
	var refreshResp map[string]any
	json.NewDecoder(resp.Body).Decode(&refreshResp)
	resp.Body.Close()

	newAccessToken, ok := refreshResp["access_token"].(string)
	if !ok || newAccessToken == "" {
		t.Fatal("expected new access_token from refresh")
	}
	if refreshResp["id_token"] == nil || refreshResp["id_token"] == "" {
		t.Fatal("expected new id_token from refresh")
	}

	// Step 7: Verify the new access token works with /userinfo
	req, _ = http.NewRequest("GET", ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+newAccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo after refresh: expected 200, got %d", resp.StatusCode)
	}
	var refreshedUserInfo map[string]any
	json.NewDecoder(resp.Body).Decode(&refreshedUserInfo)
	resp.Body.Close()

	if refreshedUserInfo["sub"] != "user1" {
		t.Errorf("userinfo after refresh: expected sub=user1, got %v", refreshedUserInfo["sub"])
	}
}
