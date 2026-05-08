package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

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
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
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
