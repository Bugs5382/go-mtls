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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/Bugs5382/go-mtls"
)

// serveGRPC starts a health service behind the provider's server option and returns "127.0.0.1:port". It is dialed by
// address, not by "localhost", because grpc-go tries ::1 first and a closed port there can stall a one-shot call.
func serveGRPC(t *testing.T, p *mtls.Provider, extra ...grpc.ServerOption) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts := append([]grpc.ServerOption{p.ServerOption()}, extra...)
	srv := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	return "127.0.0.1:" + port
}

func dial(t *testing.T, target string, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(target, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func check(cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{}, opts...)
	return err
}

func wantRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("the call succeeded, want it refused")
	}
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", code, err)
	}
}

func TestMutualTLSCallSucceeds(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	cc := dial(t, serveGRPC(t, server), client.DialOption())
	if err := check(cc); err != nil {
		t.Fatal(err)
	}
}

func TestAPlaintextClientIsRefused(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	cc := dial(t, serveGRPC(t, server), grpc.WithTransportCredentials(insecure.NewCredentials()))
	wantRefused(t, check(cc))
}

func TestAClientWithoutACertificateIsRefused(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	cc := dial(t, serveGRPC(t, server), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})))
	wantRefused(t, check(cc))
}

func TestAClientTrustingAPlaintextServerIsRefused(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	ca := newCA(t)
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	wantRefused(t, check(dial(t, "127.0.0.1:"+port, client.DialOption())))
}

func TestAClientFromAnotherCAIsRefused(t *testing.T) {
	server := newProvider(t, newIdentity(t, newCA(t), leaf{names: []string{"localhost"}}))
	other := newCA(t)
	client := newProvider(t, newIdentity(t, other, leaf{names: []string{"client"}}))
	wantRefused(t, check(dial(t, serveGRPC(t, server), client.DialOption())))
}

func TestAServerFromAnotherCAIsRefused(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, newCA(t), leaf{names: []string{"localhost"}}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	wantRefused(t, check(dial(t, serveGRPC(t, server), client.DialOption())))
}

func TestAnExpiredClientCertificateIsRefused(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}, notAfter: time.Now().Add(-time.Minute)}))
	wantRefused(t, check(dial(t, serveGRPC(t, server), client.DialOption())))
}

func TestAnExpiredServerCertificateIsRefused(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"localhost"}, notAfter: time.Now().Add(-time.Minute)}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	wantRefused(t, check(dial(t, serveGRPC(t, server), client.DialOption())))
}

func TestTheServerNameMustMatchTheDialedName(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"other-service"}}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	wantRefused(t, check(dial(t, serveGRPC(t, server), client.DialOption())))
}

func TestTLS12ClientsAreRefused(t *testing.T) {
	ca := newCA(t)
	server := newProvider(t, newIdentity(t, ca, leaf{names: []string{"localhost"}}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	cert := newIdentity(t, ca, leaf{names: []string{"client"}})
	client := newProvider(t, cert)
	old := client.ClientConfig()
	old.MinVersion, old.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	wantRefused(t, check(dial(t, serveGRPC(t, server), grpc.WithTransportCredentials(credentials.NewTLS(old)))))
}

// peerSerials runs one call and returns the serial of the server certificate the client saw.
func peerSerials(t *testing.T, cc *grpc.ClientConn) int64 {
	t.Helper()
	var p peer.Peer
	if err := check(cc, grpc.Peer(&p)); err != nil {
		t.Fatalf("call failed: %v", err)
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		t.Fatalf("auth info is %T, want TLS", p.AuthInfo)
	}
	return info.State.PeerCertificates[0].SerialNumber.Int64()
}

func TestRenewedFilesAreUsedWithoutARestartWhileACallLoopRuns(t *testing.T) {
	ca := newCA(t)
	serverID := newIdentity(t, ca, leaf{names: []string{"localhost"}})
	clientID := newIdentity(t, ca, leaf{names: []string{"client"}})
	server, client := newProvider(t, serverID), newProvider(t, clientID)

	var seenClient atomic.Int64
	record := grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if p, ok := peer.FromContext(ctx); ok {
			if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.PeerCertificates) > 0 {
				seenClient.Store(info.State.PeerCertificates[0].SerialNumber.Int64())
			}
		}
		return h(ctx, req)
	})
	// A short connection age makes the client reconnect, so the loop meets the new certificates without being stopped.
	age := grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: 150 * time.Millisecond, MaxConnectionAgeGrace: time.Second})
	cc := dial(t, serveGRPC(t, server, record, age), client.DialOption())

	oldServer := peerSerials(t, cc)
	var calls, failures atomic.Int64
	var firstErr atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			calls.Add(1)
			if err := check(cc); err != nil {
				failures.Add(1)
				firstErr.CompareAndSwap(nil, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	time.Sleep(300 * time.Millisecond)
	newServerCert := ca.issue(t, leaf{names: []string{"localhost"}})
	newClientCert := ca.issue(t, leaf{names: []string{"client"}})
	serverID.writeLeaf(t, newServerCert)
	clientID.writeLeaf(t, newClientCert)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (peerSerials(t, cc) != newServerCert.serial || seenClient.Load() != newClientCert.serial) {
		time.Sleep(50 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if got := peerSerials(t, cc); got != newServerCert.serial || got == oldServer {
		t.Fatalf("the client still sees server certificate %d, want %d", got, newServerCert.serial)
	}
	if got := seenClient.Load(); got != newClientCert.serial {
		t.Fatalf("the server still sees client certificate %d, want %d", got, newClientCert.serial)
	}
	if failures.Load() != 0 {
		t.Fatalf("%d of %d calls failed during the rotation, first: %v", failures.Load(), calls.Load(), firstErr.Load())
	}
	if calls.Load() < 20 {
		t.Fatalf("only %d calls ran, the loop did not exercise the rotation", calls.Load())
	}
}

func TestANewCAIsTrustedOnceItsFileChanges(t *testing.T) {
	oldCA, newCAuth := newCA(t), newCA(t)
	serverID := newIdentity(t, oldCA, leaf{names: []string{"localhost"}})
	server := newProvider(t, serverID)
	clientID := newIdentity(t, newCAuth, leaf{names: []string{"client"}})
	client := newProvider(t, clientID)
	// The client trusts only the new CA, so it refuses the server until the server's certificate is replaced.
	cc := dial(t, serveGRPC(t, server), client.DialOption())
	wantRefused(t, check(cc))

	serverID.writeLeaf(t, newCAuth.issue(t, leaf{names: []string{"localhost"}}))
	// The server must now trust the client's issuer too: an overlapping bundle of both roots.
	serverID.writeCA(t, append(append([]byte{}, oldCA.pem...), newCAuth.pem...))
	deadline := time.Now().Add(5 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = check(cc); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the new CA was never picked up: %v", err)
}

func TestABrokenRenewalKeepsTheLastGoodFilesAndIsReported(t *testing.T) {
	ca := newCA(t)
	serverID := newIdentity(t, ca, leaf{names: []string{"localhost"}})
	var mu sync.Mutex
	var reported []error
	server := newProvider(t, serverID, mtls.WithErrorHandler(func(err error) {
		mu.Lock()
		defer mu.Unlock()
		reported = append(reported, err)
	}))
	client := newProvider(t, newIdentity(t, ca, leaf{names: []string{"client"}}))
	cc := dial(t, serveGRPC(t, server), client.DialOption())
	if err := check(cc); err != nil {
		t.Fatal(err)
	}
	replace(t, serverID.files.Cert, []byte("half written"))
	for range 3 {
		other := dial(t, cc.Target(), client.DialOption())
		if err := check(other); err != nil {
			t.Fatalf("the server stopped serving after a broken renewal: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reported) == 0 {
		t.Fatal("the broken renewal was not reported")
	}
	var fe *mtls.FileError
	if errors.As(reported[0], &fe) {
		t.Fatalf("a parse failure should not be a missing-file error: %v", reported[0])
	}
}
