# oidc-mock Design Spec

A minimalist OIDC provider for local web app development, written in Go.

## Goals

- Provide a fake OIDC identity provider that web apps can authenticate against during local development
- Zero-config startup with sensible defaults — works out of the box
- Single static binary with no runtime dependencies
- Small Docker image for containerized dev environments

## Non-Goals

- Production use
- Full OIDC/OAuth2 spec compliance (only Authorization Code flow)
- Persistence across restarts
- Refresh tokens, PKCE, or token revocation
- Automated/integration test library API

## Architecture

A single Go HTTP server exposing these endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/authorize` | GET | Starts auth code flow, shows user picker UI |
| `/token` | POST | Exchanges auth code for ID token + access token |
| `/jwks` | GET | JSON Web Key Set (public key for token verification) |
| `/userinfo` | GET | Returns claims for the authenticated user |

All state is in-memory: RSA key pair, auth codes, access token-to-user mappings. Nothing is persisted to disk.

### Startup

1. Generate an ephemeral RSA key pair (used to sign JWTs)
2. Load configuration (config file, then env var overrides, then defaults)
3. Start HTTP server

### Authorization Code Flow

1. Client redirects user to `/authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...&nonce=...`
2. Server validates `client_id` and `redirect_uri`, then renders the user picker page
3. User clicks a user card
4. Server generates a single-use auth code, stores it in memory with the selected user and nonce, redirects to `redirect_uri?code=...&state=...`
5. Client sends `POST /token` with `grant_type=authorization_code&code=...&client_id=...&client_secret=...&redirect_uri=...`
6. Server validates the code, client credentials, and redirect URI, then returns an ID token (JWT) and an opaque access token
7. Client can optionally call `GET /userinfo` with the access token to get user claims

## Configuration

A single optional YAML config file, specified via `--config` flag or `OIDC_CONFIG` env var.

```yaml
port: 8080
issuer: http://localhost:8080
clients:
  - id: my-app
    secret: my-secret
    redirect_uris:
      - http://localhost:3000/callback
users:
  - sub: user1
    email: alice@example.com
    name: Alice
    roles: [admin]
  - sub: user2
    email: bob@example.com
    name: Bob
    roles: [viewer]
```

### Defaults

When no config file is provided:

- **port**: `8080`
- **issuer**: `http://localhost:8080`
- **clients**: one default client `id: default`, `secret: secret`, `redirect_uris: [http://localhost:8080/callback]`
- **users**: two default users:
  - `sub: user1, email: alice@example.com, name: Alice, roles: [admin]`
  - `sub: user2, email: bob@example.com, name: Bob, roles: [viewer]`

### Override Priority

env vars > config file > defaults

Available env vars: `OIDC_PORT`, `OIDC_ISSUER`, `OIDC_CONFIG`.

### Custom Claims

Any key in a user object beyond the standard fields (`sub`, `email`, `name`) is treated as a custom claim and included in the ID token and userinfo response. For example, `roles`, `department`, `tenant_id` — whatever the consuming app needs.

## User Picker UI

The `/authorize` endpoint renders an HTML page listing all configured users as clickable cards. Each card displays the user's name, email, and roles. Clicking a card immediately completes the auth flow — no passwords, no forms.

The HTML template and minimal CSS are embedded in the Go binary via `embed.FS`. No JavaScript frameworks.

## Tokens

### ID Token (JWT)

Signed with the ephemeral RSA key (RS256). Contains:

- `iss` — issuer URL
- `sub` — user's subject identifier
- `aud` — client ID
- `exp` — expiration (1 hour from issuance)
- `iat` — issued at
- `nonce` — echoed from the authorize request
- All user claims (email, name, custom claims)

### Access Token

Opaque random string. The server maintains an in-memory map from access token to user, used by the `/userinfo` endpoint.

Expires after 1 hour. No refresh tokens — re-authenticate if expired.

### Auth Codes

Random string, single-use, expires after 60 seconds. Stored in an in-memory map keyed by code value, containing the associated user, client ID, redirect URI, and nonce.

## Client Validation

The `/token` endpoint validates:

- `client_id` matches a configured client
- `client_secret` matches
- `redirect_uri` matches one of the client's configured redirect URIs
- Auth code is valid, unused, and not expired

The `/authorize` endpoint validates `client_id` and `redirect_uri` before showing the user picker. On validation failure, it renders a plain-text error page (not a redirect) describing the issue — this is a dev tool, so clear error messages are more useful than spec-compliant error redirects.

## Docker

Multi-stage Dockerfile:

- **Build stage**: `golang` image, compile the binary with CGO disabled
- **Runtime stage**: `scratch` or `alpine`, copy the binary
- Resulting image under 20MB
- Config file mountable via volume: `-v ./config.yaml:/config.yaml`
- Example: `docker run -p 8080:8080 -v ./config.yaml:/config.yaml oidc-mock --config /config.yaml`

## Technology Choices

- **Language**: Go
- **Dependencies**: stdlib + a JWT signing library (e.g., `golang-jwt/jwt`)
- **Config parsing**: `gopkg.in/yaml.v3`
- **No web framework**: stdlib `net/http` is sufficient for 5 endpoints
