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

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// Option changes how a [Provider] behaves.
type Option func(*Provider)

// WithErrorHandler sets where a renewal that cannot be loaded is reported. The last good files stay in use. The
// handler is called with the provider's lock held, so it must not call back into the provider.
func WithErrorHandler(fn func(error)) Option { return func(p *Provider) { p.onError = fn } }

// Provider holds the current certificate, key and CA, and reloads them when their files change. It is safe for
// concurrent use.
type Provider struct {
	files   Files
	onError func(error)

	mu      sync.Mutex
	cur     *material
	stamps  [3]stamp
	lastErr string
}

type material struct {
	cert tls.Certificate
	pool *x509.CertPool
}

type stamp struct {
	mod  time.Time
	size int64
}

// NewProvider loads the three files and returns a provider that keeps them current. It fails with a
// [FileError] when a file is missing or unreadable, and with a descriptive error when one is not valid PEM.
func NewProvider(files Files, opts ...Option) (*Provider, error) {
	for _, f := range []struct{ role, path string }{{"certificate", files.Cert}, {"key", files.Key}, {"CA", files.CA}} {
		if f.path == "" {
			return nil, fmt.Errorf("%w: no path for the %s file", ErrNotConfigured, f.role)
		}
	}
	p := &Provider{files: files}
	for _, o := range opts {
		o(p)
	}
	stamps, err := p.stat()
	if err != nil {
		return nil, err
	}
	m, err := p.load()
	if err != nil {
		return nil, err
	}
	p.cur, p.stamps = m, stamps
	return p, nil
}

func (p *Provider) paths() [3]struct{ role, path string } {
	return [3]struct{ role, path string }{{"certificate", p.files.Cert}, {"key", p.files.Key}, {"CA", p.files.CA}}
}

func (p *Provider) stat() ([3]stamp, error) {
	var out [3]stamp
	for i, f := range p.paths() {
		info, err := os.Stat(f.path)
		if err != nil {
			return out, &FileError{Role: f.role, Path: f.path, Err: unwrapPathError(err)}
		}
		out[i] = stamp{mod: info.ModTime(), size: info.Size()}
	}
	return out, nil
}

func unwrapPathError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

func (p *Provider) read(role, path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &FileError{Role: role, Path: path, Err: unwrapPathError(err)}
	}
	return b, nil
}

func (p *Provider) load() (*material, error) {
	certPEM, err := p.read("certificate", p.files.Cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := p.read("key", p.files.Key)
	if err != nil {
		return nil, err
	}
	caPEM, err := p.read("CA", p.files.CA)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: certificate %q and key %q do not form a key pair: %w", p.files.Cert, p.files.Key, err)
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, fmt.Errorf("mtls: certificate %q: %w", p.files.Cert, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: CA file %q holds no PEM certificate", p.files.CA)
	}
	return &material{cert: cert, pool: pool}, nil
}

// current returns the files as last loaded, after re-reading them if any changed since.
func (p *Provider) current() *material {
	p.mu.Lock()
	defer p.mu.Unlock()
	stamps, err := p.stat()
	if err == nil && stamps == p.stamps {
		return p.cur
	}
	if err == nil {
		var m *material
		if m, err = p.load(); err == nil {
			p.cur, p.stamps, p.lastErr = m, stamps, ""
			return m
		}
	}
	p.report(err)
	return p.cur
}

func (p *Provider) report(err error) {
	if p.onError == nil || err.Error() == p.lastErr {
		return
	}
	p.lastErr = err.Error()
	p.onError(err)
}
