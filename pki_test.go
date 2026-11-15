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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-mtls"
)

var serial atomic.Int64

// testCA is a throwaway certificate authority for one test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf describes one certificate to issue.
type leaf struct {
	names    []string // DNS names; "localhost" also adds 127.0.0.1 and ::1
	notAfter time.Time
}

// issued is a certificate and key in PEM, plus the serial it was given.
type issued struct {
	cert, key []byte
	serial    int64
}

func (ca *testCA) issue(t *testing.T, l leaf) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if l.notAfter.IsZero() {
		l.notAfter = time.Now().Add(time.Hour)
	}
	n := serial.Add(1)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(n),
		Subject:      pkix.Name{CommonName: "test leaf"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     l.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     l.names,
	}
	for _, name := range l.names {
		if name == "localhost" {
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return issued{
		cert:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		serial: n,
	}
}

// identity is one service's three files on disk, as a mounted Secret would give them.
type identity struct {
	dir   string
	files mtls.Files
}

func newIdentity(t *testing.T, ca *testCA, l leaf) *identity {
	t.Helper()
	dir := t.TempDir()
	id := &identity{dir: dir, files: mtls.Files{
		Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt"),
	}}
	id.writeLeaf(t, ca.issue(t, l))
	id.writeCA(t, ca.pem)
	return id
}

// writeLeaf replaces the certificate and key the way a renewal does: new files moved into place.
func (id *identity) writeLeaf(t *testing.T, c issued) {
	t.Helper()
	replace(t, id.files.Key, c.key)
	replace(t, id.files.Cert, c.cert)
}

func (id *identity) writeCA(t *testing.T, bundle []byte) {
	t.Helper()
	replace(t, id.files.CA, bundle)
}

var tick atomic.Int64

// replace writes a file through a rename and gives it a modified time later than any before it, so a test never
// depends on the file system's clock granularity.
func replace(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(time.Duration(tick.Add(1)) * time.Second)
	if err := os.Chtimes(tmp, when, when); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func newProvider(t *testing.T, id *identity, opts ...mtls.Option) *mtls.Provider {
	t.Helper()
	p, err := mtls.NewProvider(id.files, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
