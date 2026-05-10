package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	KID        string
}

func GenerateKeyPair() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kidBytes := make([]byte, 12)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: key,
		KID:        base64.RawURLEncoding.EncodeToString(kidBytes),
	}, nil
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce         string         `json:"nonce,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified *bool          `json:"email_verified,omitempty"`
	Name          string         `json:"name,omitempty"`
	AtHash        string         `json:"at_hash,omitempty"`
	Custom        map[string]any `json:"-"`
}

func (c IDTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias IDTokenClaims
	b, err := json.Marshal(Alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Custom) == 0 {
		return b, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Custom {
		m[k] = v
	}
	return json.Marshal(m)
}

func (kp *KeyPair) SignIDToken(claims IDTokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kp.KID
	return token.SignedString(kp.PrivateKey)
}
