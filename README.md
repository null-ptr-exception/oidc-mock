# oidc-mock

A minimalist OIDC provider for local web app development.

Single Go binary, ~500 lines of code, 20MB Docker image. No dependencies beyond the Go standard library, a JWT library, and a YAML parser.

## Features

- **Authorization Code flow** — the standard browser-based OIDC login flow
- **User picker UI** — instead of a login form, click a card to log in as any configured user
- **YAML configuration** — define clients, users, and custom claims in a config file
- **Custom claims** — any extra fields on user objects become ID token and userinfo claims
- **Sensible defaults** — works out of the box with zero configuration
- **Docker support** — multi-stage build, ~20MB image

## Quick Start

### Zero config

```bash
go run .
```

Or with Docker:

```bash
docker build -t oidc-mock .
docker run --rm -p 8080:8080 oidc-mock
```

This starts the server on port 8080 with a default client and two users. Open `http://localhost:8080/.well-known/openid-configuration` to verify.

### With a config file

```bash
go run . --config config.yaml
```

## Configuration

All configuration is optional. Specify a YAML config file via `--config` flag or `OIDC_CONFIG` env var.

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

| Field | Default |
|---|---|
| `port` | `8080` |
| `issuer` | `http://localhost:8080` |
| `clients` | `id: default`, `secret: secret`, `redirect_uris: [http://localhost:8080/callback]` |
| `users` | Alice (admin) and Bob (viewer) |

### Environment variable overrides

Environment variables take precedence over the config file:

| Variable | Description |
|---|---|
| `OIDC_CONFIG` | Path to the YAML config file |
| `OIDC_PORT` | Server listen port |
| `OIDC_ISSUER` | Issuer URL used in tokens and discovery |

Priority: env vars > config file > defaults.

### Custom claims

Any key in a user object beyond `sub`, `email`, and `name` is treated as a custom claim. These appear in both the ID token and the `/userinfo` response. Use this for roles, departments, tenant IDs, or whatever your app needs.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/authorize` | GET | Starts auth flow, shows user picker |
| `/token` | POST | Exchanges auth code for tokens |
| `/jwks` | GET | JSON Web Key Set for token verification |
| `/userinfo` | GET | Returns claims for the authenticated user |

## Docker

Build:

```bash
docker build -t oidc-mock .
```

Run with a config file:

```bash
docker run --rm -p 8080:8080 -v ./config.yaml:/config.yaml oidc-mock --config /config.yaml
```

Docker Compose example:

```yaml
services:
  oidc-mock:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/config.yaml
    command: ["--config", "/config.yaml"]
```

## How It Works

1. Your app redirects the user to `/authorize` with the standard OIDC parameters (`client_id`, `redirect_uri`, `response_type=code`, `scope=openid`, `state`, `nonce`).
2. Instead of a login form, the user sees a picker with all configured users displayed as clickable cards.
3. Clicking a card generates an authorization code and redirects back to your app's `redirect_uri`.
4. Your app exchanges the code at `/token` for an ID token (signed JWT) and an opaque access token.
5. Optionally, your app calls `/userinfo` with the access token to fetch user claims.

The server generates a fresh RSA key pair on each startup for signing JWTs. All state (auth codes, access tokens) is in-memory and does not persist across restarts.
