# go-mtls 🐹

> 🧭 Mutual TLS for Go gRPC and HTTP services: server and client configs that reload their certificates from files, with the matching grpc options.

Services of one cluster that call each other need three things the standard library leaves to you: both ends must present a certificate, the caller must check the name it dialed, and a renewed certificate must be picked up without a restart. This package does those three things once.

## 📦 Install

```bash
go get github.com/Bugs5382/go-mtls
```

## 🚀 Use

Each service has three PEM files, usually a mounted Secret: its certificate (with any chain), its key, and the CA that signs every service in the cluster. Name them with environment variables:

| Variable | File |
|---|---|
| `MTLS_CERT_FILE` | the service's certificate |
| `MTLS_KEY_FILE` | its private key |
| `MTLS_CA_FILE` | the cluster CA |

```go
files, err := mtls.FilesFromEnv() // or mtls.Files{Cert: "...", Key: "...", CA: "..."}
if err != nil {
	log.Fatal(err) // names every variable that is not set
}
p, err := mtls.NewProvider(files)
if err != nil {
	log.Fatal(err) // a FileError names the role and the path of a missing or unreadable file
}

// gRPC server and client
srv := grpc.NewServer(p.ServerOption())
cc, err := grpc.NewClient("vault:8443", p.DialOption())

// HTTP server and client
httpSrv := p.HTTPServer(":8443", handler) // then httpSrv.ListenAndServeTLS("", "")
resp, err := p.HTTPClient().Get("https://vault:8443/health")
```

`ServerConfig()` and `ClientConfig()` return plain `*tls.Config` values for anything else.

## 🔒 What it enforces

- **Server:** requires a client certificate and verifies it against the CA file. TLS 1.3 is the minimum. A plaintext caller, a caller with no certificate, one signed by another CA and one whose certificate has expired are all refused during the handshake.
- **Client:** verifies the server's certificate against the CA file and the host name that was dialed (the short Service name). There is no skip-verify and no override of the name.
- **Authorization is yours:** a valid certificate says who is calling and grants nothing. Keep your own checks after the handshake.

## ♻️ Rotation

Each handshake compares the modified time and size of the three files with the last load and re-reads them when one changed. A connection that is open finishes on the certificate it started with, and the next one uses the new files. This matches how a mounted Secret changes: the files are replaced, not edited.

- A renewal that cannot be read (half written, not PEM, key does not match the certificate) leaves the last good files in use and goes to the function you pass with `mtls.WithErrorHandler`.
- Replacing the **root CA** is a manual step: put the old and new roots in the CA file together, renew every leaf, then remove the old root.
- `ClientConfig()` is a snapshot of the CA pool, so call it again for each new connection. `DialOption()` and `HTTPTransport()` do that for you.

### Why not grpc-go's pemfile provider?

`certprovider/pemfile` re-reads on a timer (an hour by default) rather than when a file changes, returns key material rather than a `tls.Config`, and serves gRPC only. `advancedtls` builds on it and has the same limits. These services speak gRPC and HTTP, so this package builds ordinary `crypto/tls` configs and wraps them for grpc-go.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task license  # check MIT headers (golic)
```

## ⚖️ License

MIT (c) 2026 Shane
