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
	"context"
	"errors"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ServerOption returns the option that serves gRPC over mutual TLS with the provider's files.
func (p *Provider) ServerOption() grpc.ServerOption {
	return grpc.Creds(credentials.NewTLS(p.ServerConfig()))
}

// DialOption returns the option that dials gRPC over mutual TLS with the provider's files. It checks the server
// against the target's host name and builds each connection from the files as they are now. Do not add
// grpc.WithAuthority: the name checked is the name dialed.
func (p *Provider) DialOption() grpc.DialOption {
	return grpc.WithTransportCredentials(clientCreds{p: p})
}

// clientCreds takes a fresh client config for every connection, so a renewed CA or certificate is used at once.
type clientCreds struct{ p *Provider }

func (c clientCreds) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return credentials.NewTLS(c.p.ClientConfig()).ClientHandshake(ctx, authority, conn)
}

func (c clientCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("mtls: client credentials cannot accept connections; use Provider.ServerOption")
}

func (c clientCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c clientCreds) Clone() credentials.TransportCredentials { return c }

func (c clientCreds) OverrideServerName(string) error {
	return errors.New("mtls: the server name is the name dialed and cannot be overridden")
}
