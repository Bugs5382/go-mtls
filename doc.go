// Package mtls is mutual TLS for the Go gRPC and HTTP services of one cluster: server and client configs that
// read their certificate, key and CA from files and pick up renewed files without a restart.
//
// A [Provider] watches three PEM files, the certificate (with any chain), its key and the CA that signs every
// service in the cluster. The files are named by [Files], or by the environment variables [EnvCertFile],
// [EnvKeyFile] and [EnvCAFile] through [FilesFromEnv]. [NewProvider] loads them at start and fails with a
// [FileError] naming the role and the path when one is missing or unreadable.
//
// # What it enforces
//
// The server config requires and verifies a client certificate against the CA file, and refuses anything below
// TLS 1.3, so a plaintext caller, a caller with no certificate, a caller signed by another CA and an expired
// certificate are all refused at the handshake. The client config verifies the server's certificate against the
// CA file and the host name it dialed (the short Service name), so there is no skip-verify and no authority
// override. A valid certificate says who is calling; it grants nothing, and a service keeps its own
// authorization checks.
//
// # Rotation
//
// Each handshake compares the modified time and size of the three files with the last load, and re-reads them
// when one changed. A connection that is open finishes on the certificate it started with; the next handshake
// uses the new files. A renewal that cannot be read (half written, not PEM, key does not match) is passed to
// [WithErrorHandler] and the last good files stay in use. Rotating the root CA is not automatic: put the old
// and new roots in the CA file together, renew the leaves, then drop the old root.
//
// # Why not grpc-go's pemfile provider
//
// grpc-go's certprovider/pemfile re-reads on a timer (one hour by default) rather than when a file changes,
// hands back key material rather than a tls.Config, and serves gRPC only; the advancedtls module builds on it
// and has the same limits. The services here speak both gRPC and HTTP, so this package builds ordinary
// crypto/tls configs and wraps them for grpc-go with [Provider.ServerOption] and [Provider.DialOption].
package mtls

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
