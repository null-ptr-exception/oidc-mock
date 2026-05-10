# oidc-mock

Mock OIDC provider for local development. Implements the Authorization Code flow with a user picker instead of a login form.

**Supported features:** PKCE (S256/plain), refresh tokens (`offline_access` scope), scope-based claim filtering (`openid`, `email`, `profile`), `at_hash` in ID tokens.

## Getting Started

```console
$ docker run --rm -p 8080:8080 ghcr.io/rophy/oidc-mock
Runtime OIDC_CONFIG:
---
port: 8080
issuer: http://localhost:8080
clients:
    - id: default
      secret: secret
      redirect_uris:
        - http://localhost:8080/callback
users:
    - sub: user1
      email: alice@example.com
      name: Alice
      roles:
        - admin
    - sub: user2
      email: bob@example.com
      name: Bob
      roles:
        - viewer
---
oidc-mock listening on :8080
```

Discovery doc at `http://localhost:8080/.well-known/openid-configuration`.

## Configuration

Override defaults (see Getting Started) using exactly one of:

- `OIDC_CONFIG` env var — inline YAML
- `OIDC_CONFIG_FILE` env var — path to a YAML file
- `--config <file>` flag

Setting more than one is an error. `OIDC_PORT` overrides the port independently.

Any key in a user object beyond `sub`, `email`, and `name` becomes a custom claim in the ID token and `/userinfo` response (requires `profile` scope).

### Scopes

| Scope | Claims returned |
|-------|----------------|
| `openid` | `sub` |
| `email` | `email` |
| `profile` | `name` + custom claims |
| `offline_access` | enables refresh token |

### PKCE

Supported for public clients. Pass `code_challenge` and `code_challenge_method` (`S256` or `plain`) in the authorize request, then `code_verifier` in the token request.

### docker-compose with inline config

```yaml
services:
  oidc-mock:
    image: ghcr.io/rophy/oidc-mock:latest
    ports:
      - "8080:8080"
    environment:
      OIDC_CONFIG: |
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
```

### docker-compose with config file

```yaml
services:
  oidc-mock:
    image: ghcr.io/rophy/oidc-mock:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/config.yaml
    environment:
      OIDC_CONFIG_FILE: /config.yaml
```

## Building from source

```bash
go run .
go run . --config config.yaml
```

Image published to `ghcr.io/rophy/oidc-mock`, tagged `latest` and `yyyymmdd-<hash>` on each push to master.
