# oidc-mock

Mock OIDC provider for local development. Implements the Authorization Code flow with a user picker instead of a login form.

## Quick Start

```bash
# From source
go run .

# With config
go run . --config config.yaml

# Docker
docker run --rm -p 8080:8080 ghcr.io/rophy/oidc-mock
```

Starts on `:8080` with default client (`id: default`, `secret: secret`) and two users. Discovery doc at `http://localhost:8080/.well-known/openid-configuration`.

## Configuration

Config via `--config <file>` flag, `OIDC_CONFIG_FILE` env var (file path), or `OIDC_CONFIG` env var (inline YAML). `OIDC_PORT` and `OIDC_ISSUER` override the corresponding fields.

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

Any key in a user object beyond `sub`, `email`, and `name` becomes a claim in the ID token and `/userinfo` response.

## Docker

Published to `ghcr.io/rophy/oidc-mock`. Tagged `latest` and `yyyymmdd-<hash>` on each push to master.

```yaml
# docker-compose.yaml
services:
  oidc-mock:
    image: ghcr.io/rophy/oidc-mock:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/config.yaml
    command: ["--config", "/config.yaml"]
```
