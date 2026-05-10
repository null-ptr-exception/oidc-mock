# OIDC Authorization Code Flow Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 5 spec compliance gaps in the authorization code flow: response_type validation, PKCE, at_hash, offline_access scope gating, and scope-based claim filtering.

**Architecture:** All changes stay within the existing handler/store pattern. The store gains scope tracking per access token and PKCE challenge per auth code. The `HandleToken` response conditionally includes refresh_token and filters claims by scope. The `IDTokenClaims` struct gains an `AtHash` field.

**Tech Stack:** Go 1.24, golang-jwt/v5, crypto/sha256, encoding/base64

---

### Task 1: response_type Validation

**Files:**
- Modify: `handlers.go:74-98` (HandleAuthorize)
- Modify: `handlers_test.go`

- [ ] **Step 1: Write the failing test**

In `handlers_test.go`, add:

```go
func TestAuthorizeEndpoint_InvalidResponseType(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=token&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "response_type") {
		t.Error("expected error message to mention response_type")
	}
}

func TestAuthorizeEndpoint_MissingResponseType(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestAuthorizeEndpoint_InvalidResponseType|TestAuthorizeEndpoint_MissingResponseType" -v`
Expected: FAIL (currently returns 200 with picker regardless of response_type)

- [ ] **Step 3: Implement response_type validation**

In `handlers.go` `HandleAuthorize`, add after `nonce := ...`:

```go
responseType := r.URL.Query().Get("response_type")
if responseType != "code" {
	http.Error(w, "unsupported response_type: only 'code' is supported", http.StatusBadRequest)
	return
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestAuthorize" -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add handlers.go handlers_test.go
git commit -m "fix: validate response_type=code in authorize endpoint"
```

---

### Task 2: Scope Tracking in Store

**Files:**
- Modify: `store.go`
- Modify: `handlers.go:100-128` (HandleAuthorizeCallback)
- Modify: `templates/picker.html`

This task adds scope propagation from /authorize through the auth code to the token response. The scope needs to flow: authorize request → picker form → callback → auth code data → token endpoint → stored with access token.

- [ ] **Step 1: Update store types**

In `store.go`, add `Scope` field to `AuthCodeData`:

```go
type AuthCodeData struct {
	UserSub     string
	ClientID    string
	RedirectURI string
	Nonce       string
	Scope       string
	ExpiresAt   time.Time
}
```

Change the access token store to track scope:

```go
type AccessTokenData struct {
	UserSub string
	Scope   string
}
```

Update the `Store` struct:

```go
type Store struct {
	mu            sync.Mutex
	authCodes     map[string]AuthCodeData
	accessTokens  map[string]AccessTokenData
	refreshTokens map[string]RefreshTokenData
}
```

Update `NewStore`:

```go
func NewStore() *Store {
	return &Store{
		authCodes:     make(map[string]AuthCodeData),
		accessTokens:  make(map[string]AccessTokenData),
		refreshTokens: make(map[string]RefreshTokenData),
	}
}
```

Update `SaveAccessToken`:

```go
func (s *Store) SaveAccessToken(token string, data AccessTokenData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token] = data
}
```

Update `GetUserByAccessToken` to return `AccessTokenData`:

```go
func (s *Store) GetAccessToken(token string) (AccessTokenData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.accessTokens[token]
	return data, ok
}
```

Also add `Scope` to `RefreshTokenData`:

```go
type RefreshTokenData struct {
	UserSub  string
	ClientID string
	Scope    string
}
```

- [ ] **Step 2: Update pickerData and template to pass scope**

In `handlers.go`, update `pickerData`:

```go
type pickerData struct {
	Users       []User
	ClientID    string
	RedirectURI string
	State       string
	Nonce       string
	Scope       string
}
```

In `HandleAuthorize`, read scope and pass it:

```go
scope := r.URL.Query().Get("scope")
```

Pass `Scope: scope` in the `pickerData` struct.

In `templates/picker.html`, add a hidden field inside each form (after the nonce input):

```html
<input type="hidden" name="scope" value="{{$.Scope}}">
```

- [ ] **Step 3: Update HandleAuthorizeCallback to store scope in auth code**

In `HandleAuthorizeCallback`, read the scope form value and include it:

```go
scope := r.FormValue("scope")

s.Store.SaveAuthCode(code, AuthCodeData{
	UserSub:     sub,
	ClientID:    clientID,
	RedirectURI: redirectURI,
	Nonce:       nonce,
	Scope:       scope,
	ExpiresAt:   time.Now().Add(60 * time.Second),
})
```

- [ ] **Step 4: Update HandleToken to use new store signatures**

In `HandleToken`, for the `authorization_code` case, capture scope:

```go
case "authorization_code":
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	codeData, ok := s.Store.ConsumeAuthCode(code)
	if !ok {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if codeData.ClientID != clientID || codeData.RedirectURI != redirectURI {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	userSub = codeData.UserSub
	nonce = codeData.Nonce
	scope = codeData.Scope
```

For `refresh_token`, capture scope from the refresh token data:

```go
case "refresh_token":
	rt := r.FormValue("refresh_token")
	rtData, ok := s.Store.GetRefreshToken(rt)
	if !ok {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if rtData.ClientID != clientID {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	userSub = rtData.UserSub
	scope = rtData.Scope
```

Declare `scope` alongside `userSub, nonce`:

```go
var userSub, nonce, scope string
```

Update `SaveAccessToken` call:

```go
s.Store.SaveAccessToken(accessToken, AccessTokenData{
	UserSub: user.Sub,
	Scope:   scope,
})
```

Update `SaveRefreshToken` call:

```go
s.Store.SaveRefreshToken(refreshToken, RefreshTokenData{
	UserSub:  user.Sub,
	ClientID: clientID,
	Scope:    scope,
})
```

- [ ] **Step 5: Update HandleUserinfo to use new store method**

In `HandleUserinfo`, change:

```go
data, ok := s.Store.GetAccessToken(token)
if !ok {
	w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
	http.Error(w, "invalid token", http.StatusUnauthorized)
	return
}

user := s.findUser(data.UserSub)
```

- [ ] **Step 6: Fix all existing tests that use SaveAccessToken with old signature**

In `handlers_test.go`, every `srv.Store.SaveAccessToken("atok", "user1")` becomes:

```go
srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email profile"})
```

In `integration_test.go`, the flow already goes through the full handler so no manual SaveAccessToken calls need updating there — but the integration test's authorize URL already includes `scope=openid`, which needs to become `scope=openid+email+profile+offline_access` to keep the refresh token test working (will be done in Task 4).

- [ ] **Step 7: Run all tests**

Run: `go test -v ./...`
Expected: All PASS (no behavioral change yet — just plumbing)

- [ ] **Step 8: Commit**

```bash
git add store.go handlers.go handlers_test.go integration_test.go templates/picker.html
git commit -m "refactor: add scope tracking through auth code and access token store"
```

---

### Task 3: PKCE Support

**Files:**
- Modify: `store.go` (add CodeChallenge/Method to AuthCodeData)
- Modify: `handlers.go` (HandleAuthorize, HandleAuthorizeCallback, HandleToken)
- Modify: `handlers_test.go`
- Modify: `templates/picker.html`

- [ ] **Step 1: Write failing tests**

In `handlers_test.go`, add:

```go
func TestTokenEndpoint_PKCE_S256(t *testing.T) {
	srv := newTestServer(t)

	// code_verifier is a random string; challenge = base64url(sha256(verifier))
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// SHA256 of verifier: base64url = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:       "user1",
		ClientID:      "default",
		RedirectURI:   "http://localhost:8080/callback",
		Nonce:         "n",
		Scope:         "openid",
		CodeChallenge: challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:     time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PKCE_S256_WrongVerifier(t *testing.T) {
	srv := newTestServer(t)

	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:       "user1",
		ClientID:      "default",
		RedirectURI:   "http://localhost:8080/callback",
		Nonce:         "n",
		Scope:         "openid",
		CodeChallenge: challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:     time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=wrong-verifier")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_PKCE_Plain(t *testing.T) {
	srv := newTestServer(t)

	verifier := "plainverifier123"

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:       "user1",
		ClientID:      "default",
		RedirectURI:   "http://localhost:8080/callback",
		Nonce:         "n",
		Scope:         "openid",
		CodeChallenge: verifier,
		CodeChallengeMethod: "plain",
		ExpiresAt:     time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PKCE_MissingVerifier(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:       "user1",
		ClientID:      "default",
		RedirectURI:   "http://localhost:8080/callback",
		Nonce:         "n",
		Scope:         "openid",
		CodeChallenge: "somechallenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:     time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestTokenEndpoint_PKCE" -v`
Expected: Compilation error (CodeChallenge field doesn't exist yet)

- [ ] **Step 3: Add PKCE fields to AuthCodeData**

In `store.go`, add to `AuthCodeData`:

```go
type AuthCodeData struct {
	UserSub             string
	ClientID            string
	RedirectURI         string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}
```

- [ ] **Step 4: Implement PKCE validation in HandleToken**

In `handlers.go`, add import `"crypto/sha256"` to the imports.

In the `authorization_code` case, after the existing validation, add PKCE verification:

```go
// PKCE verification
if codeData.CodeChallenge != "" {
	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if !verifyPKCE(codeData.CodeChallenge, codeData.CodeChallengeMethod, codeVerifier) {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
}
```

Add the `verifyPKCE` helper function in `handlers.go`:

```go
func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}
```

- [ ] **Step 5: Pass PKCE params through authorize flow**

In `handlers.go` `HandleAuthorize`, read PKCE params and pass them through the picker:

Update `pickerData`:

```go
type pickerData struct {
	Users         []User
	ClientID      string
	RedirectURI   string
	State         string
	Nonce         string
	Scope         string
	CodeChallenge string
	CodeChallengeMethod string
}
```

In `HandleAuthorize`, read:

```go
codeChallenge := r.URL.Query().Get("code_challenge")
codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
if codeChallenge != "" && codeChallengeMethod == "" {
	codeChallengeMethod = "plain"
}
```

Pass them to `pickerData`.

In `templates/picker.html`, add hidden fields (after scope):

```html
<input type="hidden" name="code_challenge" value="{{$.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{$.CodeChallengeMethod}}">
```

In `HandleAuthorizeCallback`, read them and include in SaveAuthCode:

```go
codeChallenge := r.FormValue("code_challenge")
codeChallengeMethod := r.FormValue("code_challenge_method")

s.Store.SaveAuthCode(code, AuthCodeData{
	UserSub:             sub,
	ClientID:            clientID,
	RedirectURI:         redirectURI,
	Nonce:               nonce,
	Scope:               scope,
	CodeChallenge:       codeChallenge,
	CodeChallengeMethod: codeChallengeMethod,
	ExpiresAt:           time.Now().Add(60 * time.Second),
})
```

- [ ] **Step 6: Update discovery endpoint**

In `HandleDiscovery`, add:

```go
"code_challenge_methods_supported": []string{"S256", "plain"},
```

- [ ] **Step 7: Run all tests**

Run: `go test -v ./...`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add store.go handlers.go handlers_test.go templates/picker.html
git commit -m "feat: add PKCE support (S256 and plain)"
```

---

### Task 4: offline_access Scope Gating

**Files:**
- Modify: `handlers.go` (HandleToken)
- Modify: `handlers_test.go`
- Modify: `integration_test.go`

- [ ] **Step 1: Write failing tests**

In `handlers_test.go`, add:

```go
func TestTokenEndpoint_NoRefreshTokenWithoutOfflineAccess(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("code1", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid email profile",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=code1&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["refresh_token"] != nil {
		t.Error("expected no refresh_token without offline_access scope")
	}
}

func TestTokenEndpoint_RefreshTokenWithOfflineAccess(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("code1", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid email profile offline_access",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=code1&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("expected refresh_token with offline_access scope")
	}
}
```

- [ ] **Step 2: Run tests to verify the first one fails**

Run: `go test -run "TestTokenEndpoint_NoRefreshTokenWithoutOfflineAccess" -v`
Expected: FAIL (currently always returns refresh_token)

- [ ] **Step 3: Implement offline_access gating**

In `handlers.go` `HandleToken`, add a helper to check scope:

```go
func hasScope(scope, target string) bool {
	for _, s := range strings.Fields(scope) {
		if s == target {
			return true
		}
	}
	return false
}
```

Replace the unconditional refresh token generation with conditional:

```go
resp := map[string]any{
	"access_token": accessToken,
	"token_type":   "Bearer",
	"expires_in":   3600,
	"id_token":     idToken,
}

if hasScope(scope, "offline_access") {
	refreshToken := GenerateRandomString(32)
	s.Store.SaveRefreshToken(refreshToken, RefreshTokenData{
		UserSub:  user.Sub,
		ClientID: clientID,
		Scope:    scope,
	})
	resp["refresh_token"] = refreshToken
}

w.Header().Set("Content-Type", "application/json")
w.Header().Set("Cache-Control", "no-store")
json.NewEncoder(w).Encode(resp)
```

- [ ] **Step 4: Update existing tests that expect refresh_token**

Update `TestTokenEndpoint_ValidExchange` — add `offline_access` to the stored auth code scope:

```go
srv.Store.SaveAuthCode("testcode", AuthCodeData{
	UserSub:     "user1",
	ClientID:    "default",
	RedirectURI: "http://localhost:8080/callback",
	Nonce:       "nonce1",
	Scope:       "openid offline_access",
	ExpiresAt:   time.Now().Add(60 * time.Second),
})
```

Update `TestTokenEndpoint_BasicAuth` similarly (add `Scope: "openid offline_access"`).

Update `TestTokenEndpoint_CodeAlreadyConsumed` (add `Scope: "openid"`).

Update `integration_test.go` — change the authorize URL scope from `scope=openid` to `scope=openid+email+profile+offline_access` and the callback formData to include scope:

```go
authURL := ts.URL + "/authorize?client_id=default&redirect_uri=" + url.QueryEscape(ts.URL+"/callback") + "&response_type=code&scope=openid+email+profile+offline_access&state=teststate&nonce=testnonce"
```

And in formData:

```go
formData := url.Values{
	"sub":          {"user1"},
	"client_id":    {"default"},
	"redirect_uri": {ts.URL + "/callback"},
	"state":        {"teststate"},
	"nonce":        {"testnonce"},
	"scope":        {"openid email profile offline_access"},
}
```

- [ ] **Step 5: Run all tests**

Run: `go test -v ./...`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add handlers.go handlers_test.go integration_test.go
git commit -m "feat: only issue refresh_token when offline_access scope is requested"
```

---

### Task 5: at_hash Claim in ID Token

**Files:**
- Modify: `crypto.go` (IDTokenClaims)
- Modify: `handlers.go` (HandleToken)
- Modify: `handlers_test.go`

- [ ] **Step 1: Write failing test**

In `handlers_test.go`, add:

```go
func TestTokenEndpoint_IDToken_ContainsAtHash(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("hashcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=hashcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	accessToken := resp["access_token"].(string)
	idTokenStr := resp["id_token"].(string)

	// Parse the ID token and check at_hash
	parsed, err := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	atHash, ok := claims["at_hash"].(string)
	if !ok || atHash == "" {
		t.Fatal("expected at_hash claim in id_token")
	}

	// Verify at_hash: left half of SHA-256 of access_token, base64url-encoded
	h := sha256.Sum256([]byte(accessToken))
	expectedAtHash := base64.RawURLEncoding.EncodeToString(h[:16])
	if atHash != expectedAtHash {
		t.Errorf("at_hash mismatch: got %s, expected %s", atHash, expectedAtHash)
	}
}
```

Add these imports to the test file: `"crypto/sha256"`, `"encoding/base64"`, `"github.com/golang-jwt/jwt/v5"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run "TestTokenEndpoint_IDToken_ContainsAtHash" -v`
Expected: FAIL (no at_hash in ID token)

- [ ] **Step 3: Add AtHash field to IDTokenClaims**

In `crypto.go`, add the field:

```go
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce  string         `json:"nonce,omitempty"`
	Email  string         `json:"email,omitempty"`
	Name   string         `json:"name,omitempty"`
	AtHash string         `json:"at_hash,omitempty"`
	Custom map[string]any `json:"-"`
}
```

- [ ] **Step 4: Compute at_hash in HandleToken**

In `handlers.go`, add `"crypto/sha256"` to imports.

After generating the access token but before signing the ID token, compute the hash:

```go
accessToken := GenerateRandomString(32)

// Compute at_hash: left half of SHA-256 of access token
atHashBytes := sha256.Sum256([]byte(accessToken))
atHash := base64.RawURLEncoding.EncodeToString(atHashBytes[:16])

now := time.Now()
idTokenClaims := IDTokenClaims{
	RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    s.Config.Issuer,
		Subject:   user.Sub,
		Audience:  jwt.ClaimStrings{clientID},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	},
	Nonce:  nonce,
	Email:  user.Email,
	Name:   user.Name,
	AtHash: atHash,
	Custom: user.Claims,
}
```

Note: this means the access token generation must be moved BEFORE the ID token construction (currently it's after). Reorder the code so access token is generated first.

- [ ] **Step 5: Run all tests**

Run: `go test -v ./...`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add crypto.go handlers.go handlers_test.go
git commit -m "feat: add at_hash claim to ID token per OIDC Core spec"
```

---

### Task 6: Scope-Based Claim Filtering

**Files:**
- Modify: `handlers.go` (HandleToken, HandleUserinfo)
- Modify: `handlers_test.go`

- [ ] **Step 1: Write failing tests**

In `handlers_test.go`, add:

```go
func TestUserinfoEndpoint_ScopeFiltering_OpenIDOnly(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Error("expected sub claim")
	}
	if claims["email"] != nil {
		t.Errorf("expected no email with openid-only scope, got %v", claims["email"])
	}
	if claims["name"] != nil {
		t.Errorf("expected no name with openid-only scope, got %v", claims["name"])
	}
}

func TestUserinfoEndpoint_ScopeFiltering_EmailScope(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Error("expected sub claim")
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email, got %v", claims["email"])
	}
	if claims["name"] != nil {
		t.Errorf("expected no name with openid+email scope, got %v", claims["name"])
	}
}

func TestUserinfoEndpoint_ScopeFiltering_ProfileScope(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid profile"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Error("expected sub claim")
	}
	if claims["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", claims["name"])
	}
	if claims["email"] != nil {
		t.Errorf("expected no email with openid+profile scope, got %v", claims["email"])
	}
	// Custom claims go under profile scope
	if claims["roles"] == nil {
		t.Error("expected custom claims (roles) with profile scope")
	}
}

func TestTokenEndpoint_IDToken_ScopeFiltering(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("scopecode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=scopecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	idTokenStr := resp["id_token"].(string)
	parsed, _ := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	claims := parsed.Claims.(jwt.MapClaims)

	if claims["sub"] != "user1" {
		t.Error("expected sub")
	}
	if claims["email"] != nil {
		t.Errorf("expected no email in id_token with openid-only scope, got %v", claims["email"])
	}
	if claims["name"] != nil {
		t.Errorf("expected no name in id_token with openid-only scope, got %v", claims["name"])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestUserinfoEndpoint_ScopeFiltering|TestTokenEndpoint_IDToken_ScopeFiltering" -v`
Expected: FAIL (currently returns all claims regardless of scope)

- [ ] **Step 3: Implement scope filtering in HandleUserinfo**

In `handlers.go`, replace the claims building in `HandleUserinfo`:

```go
claims := map[string]any{
	"sub": user.Sub,
}
if hasScope(data.Scope, "email") {
	claims["email"] = user.Email
}
if hasScope(data.Scope, "profile") {
	claims["name"] = user.Name
	for k, v := range user.Claims {
		claims[k] = v
	}
}
```

- [ ] **Step 4: Implement scope filtering in ID token construction**

In `handlers.go` `HandleToken`, build the ID token claims conditionally:

```go
idTokenClaims := IDTokenClaims{
	RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    s.Config.Issuer,
		Subject:   user.Sub,
		Audience:  jwt.ClaimStrings{clientID},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	},
	Nonce:  nonce,
	AtHash: atHash,
}

if hasScope(scope, "email") {
	idTokenClaims.Email = user.Email
}
if hasScope(scope, "profile") {
	idTokenClaims.Name = user.Name
	idTokenClaims.Custom = user.Claims
}
```

- [ ] **Step 5: Update existing tests that expect all claims**

Update `TestTokenEndpoint_ValidExchange` auth code to include `Scope: "openid email profile offline_access"` (already done in Task 4).

Update `TestUserinfoEndpoint` to store access token with full scope:

```go
srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email profile"})
```

Update `TestUserinfoEndpoint_CustomClaims` similarly (needs `profile` scope for custom claims).

Update `TestTokenEndpoint_RefreshToken` to store the refresh token with scope that includes email+profile:

```go
srv.Store.SaveRefreshToken("rt1", RefreshTokenData{
	UserSub:  "user1",
	ClientID: "default",
	Scope:    "openid email profile offline_access",
})
```

- [ ] **Step 6: Run all tests**

Run: `go test -v ./...`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add handlers.go handlers_test.go
git commit -m "feat: filter claims based on requested scopes (openid, email, profile)"
```

---

### Task 7: Update Discovery and Final Integration Test

**Files:**
- Modify: `handlers.go` (HandleDiscovery)
- Modify: `handlers_test.go`
- Modify: `integration_test.go`

- [ ] **Step 1: Update discovery document**

In `HandleDiscovery`, add `offline_access` to scopes_supported:

```go
"scopes_supported": []string{"openid", "email", "profile", "offline_access"},
```

- [ ] **Step 2: Add discovery test for new fields**

In `handlers_test.go`, update `TestDiscoveryEndpoint` to also check:

```go
grantTypes := doc["grant_types_supported"].([]any)
if len(grantTypes) != 2 || grantTypes[0] != "authorization_code" || grantTypes[1] != "refresh_token" {
	t.Errorf("unexpected grant_types_supported: %v", grantTypes)
}

challengeMethods := doc["code_challenge_methods_supported"].([]any)
if len(challengeMethods) != 2 || challengeMethods[0] != "S256" || challengeMethods[1] != "plain" {
	t.Errorf("unexpected code_challenge_methods_supported: %v", challengeMethods)
}
```

- [ ] **Step 3: Run all tests including integration**

Run: `go test -v ./...`
Expected: All PASS

- [ ] **Step 4: Run e2e tests**

Run: `go test -tags e2e -v ./e2e/`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add handlers.go handlers_test.go integration_test.go
git commit -m "feat: update discovery with offline_access scope and PKCE methods"
```
