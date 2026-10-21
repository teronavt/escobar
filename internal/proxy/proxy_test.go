// Copyright (c) 2020 Savely Krasovsky. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/L11R/httputil"
	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
	"github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestMain(m *testing.M) {
	// We need corporate proxy emulation to run tests
	proxy := goproxy.NewProxyHttpServer()
	auth.ProxyBasic(proxy, "EVIL.CORP NEEDS YOUR AUTH", func(user, password string) bool {
		return user == "test_user" && subtle.ConstantTimeCompare([]byte(password), []byte("test_password")) == 1
	})

	go func() {
		log.Fatal(http.ListenAndServe("localhost:9090", proxy))
	}()

	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestNewProxy(t *testing.T) {
	logger := zap.NewNop()

	downstreamProxyURL, _ := url.Parse("http://localhost:9090/")
	pingURL, _ := url.Parse("https://www.google.com/")

	config := &Config{
		Addr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 3128,
		},
		DownstreamProxyURL: downstreamProxyURL,
		DownstreamProxyAuth: DownstreamProxyAuth{
			User:     "test_user",
			Password: "test_password",
		},
		Kerberos: Kerberos{
			Realm: "EVIL.CORP",
			KDC: &net.TCPAddr{
				IP:   net.IPv4(10, 0, 0, 1),
				Port: 88,
			},
		},
		Timeouts: Timeouts{
			Server: ServerTimeouts{
				ReadHeaderTimeout: 30 * time.Second,
				WriteTimeout:      1 * time.Minute,
			},
			Client: ClientTimeouts{
				KeepAlivePeriod: 1 * time.Minute,
			},
			DownstreamProxy: DownstreamProxyTimeouts{
				DialTimeout:     10 * time.Second,
				KeepAlivePeriod: 1 * time.Minute,
			},
		},
		PingURL: pingURL,
	}

	confReader, err := config.Kerberos.Reader()
	require.NoError(t, err)

	krb5conf, err := krb5config.NewFromReader(confReader)
	require.NoError(t, err)

	krb5cl := client.NewWithPassword(
		config.DownstreamProxyAuth.User,
		config.Kerberos.Realm,
		config.DownstreamProxyAuth.Password,
		krb5conf,
	)

	// Dummy patch to avoid different pointers comparing
	rp := httputil.NewForwardingProxy()
	patch := monkey.Patch(httputil.NewForwardingProxy, func() *httputil.ReverseProxy {
		return rp
	})
	// nolint:errcheck
	defer patch.Unpatch()

	expected := &Proxy{
		logger:    logger,
		config:    config,
		krb5cl:    krb5cl,
		httpProxy: httputil.NewForwardingProxy(),
	}

	expected.httpProxy.ErrorLog = zap.NewStdLog(logger)
	expected.server = &http.Server{
		Addr:              config.Addr.String(),
		Handler:           expected,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadTimeout:       config.Timeouts.Server.ReadTimeout,
		ReadHeaderTimeout: config.Timeouts.Server.ReadHeaderTimeout,
		WriteTimeout:      config.Timeouts.Server.WriteTimeout,
		IdleTimeout:       config.Timeouts.Server.IdleTimeout,
	}

	actual := NewProxy(logger, config, krb5cl)
	assert.Equal(t, expected, actual)
}

func TestProxy_CheckAuth(t *testing.T) {
	logger := zap.NewNop()

	downstreamProxyURL, _ := url.Parse("http://localhost:9090/")
	httpPingURL, _ := url.Parse("http://checkip.amazonaws.com/")
	httpsPingURL, _ := url.Parse("https://checkip.amazonaws.com/")

	config := &Config{
		Addr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 31280,
		},
		DownstreamProxyURL: downstreamProxyURL,
		DownstreamProxyAuth: DownstreamProxyAuth{
			User:     "test_user",
			Password: "test_password",
		},
		Timeouts: Timeouts{
			Server: ServerTimeouts{
				ReadHeaderTimeout: 30 * time.Second,
				WriteTimeout:      1 * time.Minute,
			},
			Client: ClientTimeouts{
				KeepAlivePeriod: 1 * time.Minute,
			},
			DownstreamProxy: DownstreamProxyTimeouts{
				DialTimeout:     10 * time.Second,
				KeepAlivePeriod: 1 * time.Minute,
			},
		},
		PingURL: httpPingURL,
		Mode:    BasicMode,
	}

	p := NewProxy(logger, config, nil)

	l, err := p.Listen()
	require.NoError(t, err)

	go func() {
		require.NoError(t, p.Serve(l))
	}()

	t.Run("http", func(t *testing.T) {
		ok, err := p.CheckAuth()
		require.NoError(t, err)
		require.True(t, ok)
	})

	p.config.PingURL = httpsPingURL

	t.Run("https", func(t *testing.T) {
		ok, err := p.CheckAuth()
		require.NoError(t, err)
		require.True(t, ok)
	})

	require.NoError(t, p.Shutdown(context.Background()))
}

const testProxyAuthorization = "Basic dGVzdF91c2VyOnRlc3RfcGFzc3dvcmQ="

func TestProxy_HTTPSConnectPreemptiveAuthorization(t *testing.T) {
	downstream := listenConnectTestProxy(t)
	done := make(chan error, 1)
	var connectionCount int32

	go func() {
		pconn, err := downstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer pconn.Close()
		atomic.AddInt32(&connectionCount, 1)

		br := bufio.NewReader(pconn)
		if err := expectConnectRequest(br); err != nil {
			done <- err
			return
		}
		if _, err := io.WriteString(pconn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			done <- err
			return
		}

		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "ping" {
			done <- fmt.Errorf("tunnel payload = %q, want ping", buf)
			return
		}
		_, err = io.WriteString(pconn, "pong")
		done <- err
	}()

	client, clientReader, resp := openConnectClient(t, downstream.Addr().String())
	defer client.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err := io.WriteString(client, "ping")
	require.NoError(t, err)
	pong := make([]byte, 4)
	_, err = io.ReadFull(clientReader, pong)
	require.NoError(t, err)
	require.Equal(t, "pong", string(pong))
	require.Equal(t, int32(1), atomic.LoadInt32(&connectionCount))
	requireConnectTestDone(t, done)
}

func TestProxy_HTTPSConnectDrainsKeepAlive407(t *testing.T) {
	downstream := listenConnectTestProxy(t)
	done := make(chan error, 1)
	var connectionCount int32

	go func() {
		pconn, err := downstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer pconn.Close()
		atomic.AddInt32(&connectionCount, 1)

		br := bufio.NewReader(pconn)
		if err := expectConnectRequest(br); err != nil {
			done <- err
			return
		}
		body := "<html>proxy authentication required</html>"
		if _, err := fmt.Fprintf(pconn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Type: text/html\r\nContent-Length: %d\r\nProxy-Authenticate: Negotiate\r\nConnection: keep-alive\r\n\r\n%s", len(body), body); err != nil {
			done <- err
			return
		}
		if err := expectConnectRequest(br); err != nil {
			done <- err
			return
		}
		_, err = io.WriteString(pconn, "HTTP/1.1 200 Connection established\r\n\r\n")
		done <- err
	}()

	client, _, resp := openConnectClient(t, downstream.Addr().String())
	defer client.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(1), atomic.LoadInt32(&connectionCount))
	requireConnectTestDone(t, done)
}

func TestProxy_HTTPSConnectReconnectsAfterClosing407(t *testing.T) {
	downstream := listenConnectTestProxy(t)
	done := make(chan error, 1)
	var connectionCount int32

	go func() {
		pconn, err := downstream.Accept()
		if err != nil {
			done <- err
			return
		}
		atomic.AddInt32(&connectionCount, 1)
		br := bufio.NewReader(pconn)
		if err := expectConnectRequest(br); err != nil {
			pconn.Close()
			done <- err
			return
		}
		body := "<html>proxy authentication required</html>"
		if _, err := fmt.Fprintf(pconn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Type: text/html\r\nContent-Length: %d\r\nProxy-Authenticate: Negotiate\r\nConnection: close\r\n\r\n%s", len(body), body); err != nil {
			pconn.Close()
			done <- err
			return
		}
		pconn.Close()

		pconn, err = downstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer pconn.Close()
		atomic.AddInt32(&connectionCount, 1)
		if err := expectConnectRequest(bufio.NewReader(pconn)); err != nil {
			done <- err
			return
		}
		_, err = io.WriteString(pconn, "HTTP/1.1 200 Connection established\r\n\r\n")
		done <- err
	}()

	client, _, resp := openConnectClient(t, downstream.Addr().String())
	defer client.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(2), atomic.LoadInt32(&connectionCount))
	requireConnectTestDone(t, done)
}

func TestProxy_HTTPSConnectStopsAfterAuthenticated407(t *testing.T) {
	downstream := listenConnectTestProxy(t)
	done := make(chan error, 1)
	var connectionCount int32

	go func() {
		for i := 0; i < 2; i++ {
			pconn, err := downstream.Accept()
			if err != nil {
				done <- err
				return
			}
			atomic.AddInt32(&connectionCount, 1)
			if err := expectConnectRequest(bufio.NewReader(pconn)); err != nil {
				pconn.Close()
				done <- err
				return
			}
			if _, err := io.WriteString(pconn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
				pconn.Close()
				done <- err
				return
			}
			pconn.Close()
		}
		done <- nil
	}()

	client, _, resp := openConnectClient(t, downstream.Addr().String())
	defer client.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	requireConnectTestDone(t, done)
	require.Equal(t, int32(2), atomic.LoadInt32(&connectionCount))
}

func TestProxy_HTTPSConnectRejectsUnexpectedResponse(t *testing.T) {
	downstream := listenConnectTestProxy(t)
	done := make(chan error, 1)
	var connectionCount int32

	go func() {
		pconn, err := downstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer pconn.Close()
		atomic.AddInt32(&connectionCount, 1)
		if err := expectConnectRequest(bufio.NewReader(pconn)); err != nil {
			done <- err
			return
		}
		_, err = io.WriteString(pconn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		done <- err
	}()

	client, _, resp := openConnectClient(t, downstream.Addr().String())
	defer client.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	requireConnectTestDone(t, done)
	require.Equal(t, int32(1), atomic.LoadInt32(&connectionCount))
}

func listenConnectTestProxy(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func openConnectClient(t *testing.T, downstreamAddress string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()

	proxyAddress := startConnectProxy(t, downstreamAddress)
	client, err := net.Dial("tcp", proxyAddress)
	require.NoError(t, err)
	_, err = fmt.Fprint(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic YXR0YWNrZXI6Y3JlZGVudGlhbA==\r\n\r\n")
	require.NoError(t, err)

	reader := bufio.NewReader(client)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	return client, reader, resp
}

func startConnectProxy(t *testing.T, downstreamAddress string) string {
	t.Helper()

	downstreamURL, err := url.Parse("http://" + downstreamAddress)
	require.NoError(t, err)
	p := NewProxy(zap.NewNop(), &Config{
		Addr:               &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		DownstreamProxyURL: downstreamURL,
		DownstreamProxyAuth: DownstreamProxyAuth{
			User:     "test_user",
			Password: "test_password",
		},
		Mode: BasicMode,
		Timeouts: Timeouts{
			Client:          ClientTimeouts{KeepAlivePeriod: time.Minute},
			DownstreamProxy: DownstreamProxyTimeouts{DialTimeout: time.Second, KeepAlivePeriod: time.Minute},
		},
	}, nil)

	listener, err := p.Listen()
	require.NoError(t, err)
	go func() { _ = p.Serve(listener) }()
	t.Cleanup(func() { require.NoError(t, p.Shutdown(context.Background())) })
	return listener.Addr().String()
}

func expectConnectRequest(reader *bufio.Reader) error {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("cannot read CONNECT request: %w", err)
	}
	if req.Method != http.MethodConnect {
		return fmt.Errorf("request method = %s, want CONNECT", req.Method)
	}
	if req.Host != "example.com:443" {
		return fmt.Errorf("CONNECT host = %s, want example.com:443", req.Host)
	}
	if authorization := req.Header.Get(HeaderProxyAuthorization); authorization != testProxyAuthorization {
		return fmt.Errorf("Proxy-Authorization = %q, want Escobar-generated Basic authorization", authorization)
	}
	return nil
}

func requireConnectTestDone(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("downstream CONNECT test timed out")
	}
}
