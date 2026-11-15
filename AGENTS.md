# AGENTS.md - go-mtls

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Mutual TLS for Go gRPC and HTTP services: server and client configs that reload their certificates from files, with the matching grpc options.

It is a library with no service of its own. A `Provider` watches a certificate file, its key file and a CA file,
reloads them when their modified time or size changes, and hands out `tls.Config` values and grpc-go and
net/http helpers for mutual TLS between the services of one cluster. Two things to know before changing it:
the server config is rebuilt per handshake (`GetConfigForClient`) and the client config is rebuilt per
connection, because crypto/tls cannot swap a client's roots; and a failed reload keeps the last good files
and is reported through `WithErrorHandler`, never by dropping the connection.

## Using go-mtls

One entry point: `NewProvider(Files)` (or `FilesFromEnv()` first), then `ServerOption()` / `DialOption()` for
gRPC, `HTTPServer()` / `HTTPClient()` for HTTP, or `ServerConfig()` / `ClientConfig()` for anything else.
Never add an override for the server name, a skip-verify option or a TLS version below 1.3: the package exists
so that no service has to choose. Authorization stays in the caller; a valid certificate grants nothing.

## Layout

All code is in the root package `mtls`.

- `files.go` - `Files`, the three environment variable names, `FilesFromEnv`, `FileError`, `ErrNotConfigured`
- `provider.go` - `Provider`: load, stat-based reload, last-good fallback, `WithErrorHandler`
- `config.go` - `ServerConfig` and `ClientConfig`
- `grpc.go` - `ServerOption` and `DialOption` (the client credentials take a fresh config per connection)
- `http.go` - `HTTPServer`, `HTTPTransport` and `HTTPClient`
- `*_test.go` - external tests; `pki_test.go` makes throwaway CAs and certificates

## Build, test, lint

- Build: `task build`
- Test: `task test` (no services needed; the tests start in-process gRPC and HTTP servers on loopback). Run
  `go test -race ./...` too: the rotation test runs a call loop while the files are replaced.
- Lint: `task lint` (gofmt, golangci-lint, yamllint)
- License headers: `task license` to check, `task license:fix` to stamp

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- The package never logs: it has no logger dependency and reports a failed renewal through `WithErrorHandler`.
  Key and certificate contents never appear in an error; paths and roles do.
- A renewal test must replace files through a rename and bump the modified time (see `replace` in
  `pki_test.go`), the way a mounted Secret changes, or it depends on file system clock granularity.
- Generic wording only: say "services of one cluster", never a product or company name, in code, docs and tests.
