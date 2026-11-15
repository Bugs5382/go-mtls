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

import "crypto/tls"

// nextProtos is what both ends offer, so a gRPC or HTTP/2 call is not downgraded.
var nextProtos = []string{"h2", "http/1.1"}

// ServerConfig returns a config for a server. It requires and verifies a client certificate against the CA file,
// refuses anything below TLS 1.3, and builds each handshake from the files as they are now, so a renewed
// certificate or CA is used by the next connection without a restart.
func (p *Provider) ServerConfig() *tls.Config {
	build := func(m *material) *tls.Config {
		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    m.pool,
			Certificates: []tls.Certificate{m.cert},
			NextProtos:   nextProtos,
		}
	}
	cfg := build(p.current())
	cfg.Certificates = nil
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return build(p.current()), nil }
	return cfg
}

// ClientConfig returns a config for a client. It verifies the server's certificate against the CA file and the
// host name that was dialed, and presents the current client certificate, which a renewal replaces without a
// restart. Its CA pool is a snapshot taken when it is called, because crypto/tls cannot swap a client's roots:
// call it again for each new connection, or use [Provider.DialOption] and [Provider.HTTPTransport], which do.
func (p *Provider) ClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              p.current().pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { c := p.current().cert; return &c, nil },
		NextProtos:           nextProtos,
	}
}
