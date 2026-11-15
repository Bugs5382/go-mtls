package mtls_test

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

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func serveHTTP(t *testing.T, id *identity) string {
	t.Helper()
	p := newProvider(t, id)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := p.HTTPServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.Proto)
	}))
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	return "localhost:" + port
}

func get(t *testing.T, c *http.Client, url string) (string, error) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestHTTPMutualTLSRoundTripUsesHTTP2(t *testing.T) {
	ca := newCA(t)
	addr := serveHTTP(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	got, err := get(t, client.HTTPClient(), "https://"+addr+"/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello HTTP/2.0" {
		t.Fatalf("body = %q, want a reply over HTTP/2", got)
	}
}

func TestHTTPPlaintextAndCertificatelessClientsAreRefused(t *testing.T) {
	ca := newCA(t)
	addr := serveHTTP(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	if body, err := get(t, &http.Client{Timeout: 3 * time.Second}, "http://"+addr+"/"); err == nil && body == "hello HTTP/1.1" {
		t.Fatalf("a plaintext request was served: %q", body)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	bare := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	if _, err := get(t, bare, "https://"+addr+"/"); err == nil {
		t.Fatal("a client with no certificate was served")
	}
}

func TestHTTPClientRefusesAServerForTheWrongName(t *testing.T) {
	ca := newCA(t)
	addr := serveHTTP(t, newIdentity(t, ca, leaf{names: []string{"other-service"}}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	if _, err := get(t, client.HTTPClient(), "https://"+addr+"/"); err == nil {
		t.Fatal("the server's name was not checked")
	}
}
