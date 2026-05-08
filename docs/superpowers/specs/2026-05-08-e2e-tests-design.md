# E2E Tests Design Spec

End-to-end tests for oidc-mock using Playwright via playwright-go, exercising the full browser-based OIDC flow.

## Goals

- Verify the OIDC authorization code flow works end-to-end through a real browser
- Catch regressions in the user picker UI and redirect behavior
- Test error handling for invalid requests

## Non-Goals

- Testing token cryptographic validity (covered by Go unit/integration tests)
- Testing non-browser flows
- Performance or load testing

## Architecture

A Go test file using `playwright-community/playwright-go` that:

1. Builds and starts the `oidc-mock` binary on port 19090
2. Launches a headless browser via Playwright
3. Runs test scenarios against the live server
4. Tears down after all tests complete

Tests live in `e2e/e2e_test.go` as a separate Go package (`package e2e`). They are excluded from normal `go test ./...` via a build tag (`//go:build e2e`).

## Server Lifecycle

`TestMain` handles setup and teardown:

1. Build the binary: `go build -o /tmp/oidc-mock-e2e .` from the project root
2. Start the binary: `/tmp/oidc-mock-e2e` (uses default config, port overridden to 19090 via env var `OIDC_PORT=19090`)
3. Poll `http://localhost:19090/.well-known/openid-configuration` until ready (timeout 5 seconds)
4. Install Playwright browsers if needed, launch headless Chromium
5. Run tests
6. Kill the server process, close browser

## Test Cases

### TestPickerDisplaysUsers

- Navigate to `http://localhost:19090/authorize?client_id=default&redirect_uri=http://localhost:19090/callback&response_type=code&scope=openid&state=test&nonce=test`
- Assert the page contains text "Alice" and "alice@example.com"
- Assert the page contains text "Bob" and "bob@example.com"
- Assert the page title or heading contains "oidc-mock"

### TestFullLoginFlow

- Navigate to the authorize URL (same as above)
- Click the button/card containing "Alice"
- Wait for navigation to complete
- Assert the resulting URL starts with `http://localhost:19090/callback`
- Assert the URL query params contain `code` (non-empty) and `state=test`
- Extract the `code` from the URL
- Use `playwright.APIRequestContext` (or stdlib `http.Post`) to POST `/token` with `grant_type=authorization_code&code=<code>&client_id=default&client_secret=secret&redirect_uri=http://localhost:19090/callback`
- Assert the response status is 200
- Assert the JSON response contains non-empty `id_token` and `access_token` fields

### TestInvalidClientShowsError

- Navigate to `http://localhost:19090/authorize?client_id=nonexistent&redirect_uri=http://localhost:19090/callback&response_type=code&scope=openid`
- Assert the page contains text "unknown client_id" (the error message from HandleAuthorize)
- Assert no redirect occurred

### TestInvalidRedirectURIShowsError

- Navigate to `http://localhost:19090/authorize?client_id=default&redirect_uri=http://evil.com/callback&response_type=code&scope=openid`
- Assert the page contains text "invalid redirect_uri"
- Assert no redirect occurred

## File Structure

```
e2e/
  e2e_test.go    # All test cases + TestMain setup/teardown
```

## Dependencies

- `github.com/playwright-community/playwright-go` — Go Playwright bindings
- Playwright browsers installed via `playwright.Install()` or CLI

## CI Integration

Add a new job to `.github/workflows/ci.yaml`:

```yaml
e2e:
  needs: test
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with:
        go-version: "1.24"
    - run: go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps chromium
    - run: go test -tags e2e -v ./e2e/
```

## Technology Choices

- **playwright-go** over Node Playwright: keeps the project pure Go, no Node/npm tooling needed
- **Build tag `e2e`**: separates slow browser tests from fast unit tests
- **Hardcoded port 19090**: avoids conflict with a locally running oidc-mock on 8080
- **Headless Chromium**: fast, no display needed in CI
