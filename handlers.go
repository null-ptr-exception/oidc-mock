package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

//go:embed templates
var templateFS embed.FS

var pickerTmpl = template.Must(template.ParseFS(templateFS, "templates/picker.html"))

type Server struct {
	Config  Config
	KeyPair *KeyPair
	Store   *Store
}

func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                s.Config.Issuer,
		"authorization_endpoint":                s.Config.Issuer + "/authorize",
		"token_endpoint":                        s.Config.Issuer + "/token",
		"jwks_uri":                              s.Config.Issuer + "/jwks",
		"userinfo_endpoint":                     s.Config.Issuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "email", "name"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &s.KeyPair.PrivateKey.PublicKey
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": s.KeyPair.KID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

type pickerData struct {
	Users       []User
	ClientID    string
	RedirectURI string
	State       string
	Nonce       string
}

func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	client := s.findClient(clientID)
	if client == nil {
		http.Error(w, fmt.Sprintf("unknown client_id: %s", clientID), http.StatusBadRequest)
		return
	}
	if !s.validRedirectURI(client, redirectURI) {
		http.Error(w, fmt.Sprintf("invalid redirect_uri: %s (allowed: %v)", redirectURI, client.RedirectURIs), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	pickerTmpl.Execute(w, pickerData{
		Users:       s.Config.Users,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
		Nonce:       nonce,
	})
}

func (s *Server) HandleAuthorizeCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	sub := r.FormValue("sub")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")

	code := GenerateRandomString(16)
	s.Store.SaveAuthCode(code, AuthCodeData{
		UserSub:     sub,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Nonce:       nonce,
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) findClient(id string) *Client {
	for i := range s.Config.Clients {
		if s.Config.Clients[i].ID == id {
			return &s.Config.Clients[i]
		}
	}
	return nil
}

func (s *Server) validRedirectURI(c *Client, uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	clientID, clientSecret, basicOk := r.BasicAuth()
	if !basicOk {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := s.findClient(clientID)
	if client == nil || client.Secret != clientSecret {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	codeData, ok := s.Store.ConsumeAuthCode(code)
	if !ok {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if codeData.ClientID != clientID || codeData.RedirectURI != redirectURI {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	user := s.findUser(codeData.UserSub)
	if user == nil {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	now := time.Now()
	idTokenClaims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Config.Issuer,
			Subject:   user.Sub,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Nonce:  codeData.Nonce,
		Email:  user.Email,
		Name:   user.Name,
		Custom: user.Claims,
	}

	idToken, err := s.KeyPair.SignIDToken(idTokenClaims)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	accessToken := GenerateRandomString(32)
	s.Store.SaveAccessToken(accessToken, user.Sub)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (s *Server) findUser(sub string) *User {
	for i := range s.Config.Users {
		if s.Config.Users[i].Sub == sub {
			return &s.Config.Users[i]
		}
	}
	return nil
}

func (s *Server) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	sub, ok := s.Store.GetUserByAccessToken(token)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	user := s.findUser(sub)
	if user == nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}

	claims := map[string]any{
		"sub":   user.Sub,
		"email": user.Email,
		"name":  user.Name,
	}
	for k, v := range user.Claims {
		claims[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func jsonError(w http.ResponseWriter, errCode string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}
