// Copyright (c) 2020 Savely Krasovsky. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/L11R/httputil"

	"github.com/jcmturner/gokrb5/v8/client"
	"go.uber.org/zap"
)

const (
	LogEntryCtx              = "log_entry"
	HeaderProxyAuthorization = "Proxy-Authorization"
)

type Proxy struct {
	logger    *zap.Logger
	config    *Config
	krb5cl    *client.Client
	server    *http.Server
	httpProxy *httputil.ReverseProxy
}

// NewProxy returns Proxy instance
func NewProxy(logger *zap.Logger, config *Config, krb5cl *client.Client) *Proxy {
	fp := httputil.NewForwardingProxy()
	fp.ErrorHandler = httpErrorHandler

	p := &Proxy{
		logger:    logger,
		config:    config,
		krb5cl:    krb5cl,
		httpProxy: fp,
	}

	p.httpProxy.ErrorLog = zap.NewStdLog(logger)
	p.server = &http.Server{
		Addr:    config.Addr.String(),
		Handler: p,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		// Timeouts
		ReadTimeout:       config.Timeouts.Server.ReadTimeout,
		ReadHeaderTimeout: config.Timeouts.Server.ReadHeaderTimeout,
		WriteTimeout:      config.Timeouts.Server.WriteTimeout,
		IdleTimeout:       config.Timeouts.Server.IdleTimeout,
	}

	return p
}

// CheckAuth checks auth against Ping URL; should be called after starting proxy server itself
func (p *Proxy) CheckAuth() (bool, error) {
	u, err := url.Parse("http://" + p.config.Addr.String())
	if err != nil {
		return false, fmt.Errorf("invalid proxy url: %w", err)
	}

	// We need http client with custom transport
	httpClient := http.DefaultClient

	tr := http.DefaultTransport
	// Pass our newly deployed local proxy
	tr.(*http.Transport).Proxy = http.ProxyURL(u)
	// We check it against corporate proxy, so it usually use MITM
	tr.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	httpClient.Transport = tr

	req, err := http.NewRequest("GET", p.config.PingURL.String(), nil)
	if err != nil {
		return false, fmt.Errorf("cannot create request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req = req.WithContext(ctx)

	if err := p.setProxyAuthorizationHeader(req); err != nil {
		return false, fmt.Errorf("cannot set authorization header: %w", err)
	}

	repeat := true

Again:
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("cannot do request: %w", err)
	}
	//noinspection ALL
	defer resp.Body.Close()

	if _, err := ioutil.ReadAll(resp.Body); err != nil {
		return false, fmt.Errorf("cannot read body: %w", err)
	}

	if resp.StatusCode == http.StatusProxyAuthRequired && repeat {
		repeat = false
		goto Again
	}

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, nil
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := p.logger.With(
		zap.String("http_proto", req.Proto),
		zap.String("http_method", req.Method),
		zap.String("user_agent", req.UserAgent()),
		zap.String("uri", req.RequestURI),
	)
	// nolint:staticcheck
	req = req.WithContext(context.WithValue(context.Background(), LogEntryCtx, logger))

	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				logger.Error("Panic recovered", zap.Error(err))
			}

			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	}()

	logger.Debug("Request started")

	if req.URL.Scheme == "http" {
		p.http(rw, req)
	} else {
		p.https(rw, req)
	}

	logger.Debug("Request completed")
}

func httpErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	logger := req.Context().Value(LogEntryCtx).(*zap.Logger)

	if errors.Is(err, context.Canceled) {
		logger.Debug("http: proxy client disconnected")
		return
	}

	logger.Error("http: proxy error", zap.Error(err))
	rw.WriteHeader(http.StatusBadGateway)
}

func (p *Proxy) http(rw http.ResponseWriter, req *http.Request) {
	tr := http.DefaultTransport
	tr.(*http.Transport).Proxy = http.ProxyURL(p.config.DownstreamProxyURL)

	if err := p.setProxyAuthorizationHeader(req); err != nil {
		httpErrorHandler(rw, req, fmt.Errorf("cannot set authorization header: %w", err))
		return
	}

	p.httpProxy.ServeHTTP(rw, req)
}

func httpsErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	logger := req.Context().Value(LogEntryCtx).(*zap.Logger)

	logger.Error("https: proxy error", zap.Error(err))
	rw.WriteHeader(http.StatusBadGateway)
}

func httpsErrorHijackedHandler(brw *bufio.ReadWriter, req *http.Request, err error) {
	logger := req.Context().Value(LogEntryCtx).(*zap.Logger)

	logger.Error("https: proxy error", zap.Error(err))

	resp := newResponse(http.StatusBadGateway, nil, req)
	if err := resp.Write(brw); err != nil {
		logger.Error("Cannot write response", zap.Error(err))
	}
	if err := brw.Flush(); err != nil {
		logger.Error("Cannot flush writer", zap.Error(err))
	}
}

func (p *Proxy) https(rw http.ResponseWriter, req *http.Request) {
	logger := req.Context().Value(LogEntryCtx).(*zap.Logger)

	// Check that we are handling CONNECT
	if req.Method != http.MethodConnect {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// Take control of the connection
	hj, ok := rw.(http.Hijacker)
	if !ok {
		httpsErrorHandler(rw, req, fmt.Errorf("hijacking is not supported"))
		return
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		httpsErrorHandler(rw, req, fmt.Errorf("hijack failed: %w", err))
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("Cannot close connection", zap.Error(err))
		}
	}()

	// Set Keep-Alive
	if tconn, ok := conn.(*net.TCPConn); ok {
		if err := tconn.SetKeepAlive(true); err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot turn on keep-alive: %w", err))
			return
		}
		if err := tconn.SetKeepAlivePeriod(p.config.Timeouts.Client.KeepAlivePeriod); err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot set keep-alive period: %w", err))
			return
		}
	}

	// Set client connection timeouts
	now := time.Now()
	if p.config.Timeouts.Client.ReadTimeout.Nanoseconds() != 0 {
		if err := conn.SetReadDeadline(now.Add(p.config.Timeouts.Client.ReadTimeout)); err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot set read timeout for connection with client: %w", err))
			return
		}
	}
	if p.config.Timeouts.Client.WriteTimeout.Nanoseconds() != 0 {
		if err := conn.SetWriteDeadline(now.Add(p.config.Timeouts.Client.WriteTimeout)); err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot set write timeout for connection with client: %w", err))
			return
		}
	}

	p.connectAndCopy(conn, brw, req)
}

// connectAndCopy connects to downstream proxy, authenticates if there is a need and copies traffic between connections
func (p *Proxy) connectAndCopy(conn net.Conn, brw *bufio.ReadWriter, req *http.Request) {
	logger := req.Context().Value(LogEntryCtx).(*zap.Logger)

	// Always replace client-supplied credentials with credentials for the explicitly
	// configured downstream proxy before the first CONNECT attempt.
	if err := p.setProxyAuthorizationHeader(req); err != nil {
		httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot set authorization header: %w", err))
		return
	}

	var pconn net.Conn
	var pbw *bufio.Writer
	var pbr *bufio.Reader
	defer func() {
		if pconn != nil {
			if err := pconn.Close(); err != nil {
				logger.Error("Cannot close connection", zap.Error(err))
			}
		}
	}()

	// A challenge can require a fresh SPNEGO token, but do not loop forever when
	// the downstream proxy rejects already-authenticated CONNECT requests.
	const maxAuthenticationRetries = 1
	for authenticationRetries := 0; ; {
		if pconn == nil {
			var err error
			pconn, err = p.dialDownstreamProxy(logger)
			if err != nil {
				httpsErrorHijackedHandler(brw, req, err)
				return
			}
			pbw = bufio.NewWriter(pconn)
			pbr = bufio.NewReader(pconn)
		}

		if err := req.Write(pbw); err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot write request into proxy connection: %w", err))
			return
		}
		if err := pbw.Flush(); err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot flush writer to commit request into proxy connection: %w", err))
			return
		}

		resp, err := http.ReadResponse(pbr, req)
		if err != nil {
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot read response from proxy connection: %w", err))
			return
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// A successful CONNECT has no HTTP response body; subsequent bytes are
			// tunnel data and must remain available to the connection copier.
			resp.Body = nil
			if err := resp.Write(brw); err != nil {
				httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot write response from proxy into client connection: %w", err))
				return
			}
			if err := brw.Flush(); err != nil {
				httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot flush writer to commit response from proxy into client connection: %w", err))
				return
			}
			goto CopyTunnel

		case http.StatusProxyAuthRequired:
			if authenticationRetries >= maxAuthenticationRetries {
				resp.Body.Close()
				httpsErrorHijackedHandler(brw, req, fmt.Errorf("downstream proxy rejected authenticated CONNECT request"))
				return
			}

			// A keep-alive response must be fully consumed before parsing the next
			// response on this HTTP/1.x connection. Do not drain a connection which
			// the proxy has explicitly marked for closure.
			if !resp.Close {
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					resp.Body.Close()
					httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot drain proxy authentication response: %w", err))
					return
				}
			}
			if err := resp.Body.Close(); err != nil {
				httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot close proxy authentication response: %w", err))
				return
			}

			if resp.Close {
				if err := pconn.Close(); err != nil {
					logger.Error("Cannot close connection", zap.Error(err))
				}
				pconn = nil
			}

			if err := p.setProxyAuthorizationHeader(req); err != nil {
				httpsErrorHijackedHandler(brw, req, fmt.Errorf("cannot refresh authorization header: %w", err))
				return
			}
			authenticationRetries++

		default:
			resp.Body.Close()
			logger.Warn("Proxy did not return 200 Connection Established", zap.Int("proxy_resp_code", resp.StatusCode))
			httpsErrorHijackedHandler(brw, req, fmt.Errorf("unexpected response from downstream proxy: %s", resp.Status))
			return
		}
	}

CopyTunnel:

	// Start traffic copying inside newly created tunnel
	errc := make(chan error, 1)
	cc := connectCopier{
		logger:  logger,
		client:  conn,
		backend: pconn,
	}
	go cc.copyToBackend(errc)
	go cc.copyFromBackend(errc)

	logger.Debug("CONNECT tunnel opened")
	defer logger.Debug("CONNECT tunnel closed")

	err := <-errc
	if err == nil {
		err = <-errc
	}

	if err != nil {
		httpsErrorHijackedHandler(brw, req, fmt.Errorf("traffic copying inside tunnel failed: %w", err))
		return
	}

	logger.Debug("Traffic copied successfully")
}

func (p *Proxy) dialDownstreamProxy(logger *zap.Logger) (net.Conn, error) {
	for retries := 0; ; retries++ {
		pconn, err := net.DialTimeout("tcp", p.config.DownstreamProxyURL.Host, p.config.Timeouts.DownstreamProxy.DialTimeout)
		if err == nil {
			if err := p.configureDownstreamProxyConnection(pconn); err != nil {
				pconn.Close()
				return nil, err
			}
			return pconn, nil
		}

		if retries >= p.config.DownstreamProxyDialRetries {
			return nil, fmt.Errorf("cannot connect to downstream proxy: %w", err)
		}

		logger.Error("Connection to downstream proxy failed.", zap.Error(err))
		time.Sleep(time.Second)
		logger.Debug("Downstream proxy dial retry.", zap.Int("retries", retries+1))
	}
}

func (p *Proxy) configureDownstreamProxyConnection(pconn net.Conn) error {
	if tconn, ok := pconn.(*net.TCPConn); ok {
		if err := tconn.SetKeepAlive(true); err != nil {
			return fmt.Errorf("cannot turn on keep-alive: %w", err)
		}
		if err := tconn.SetKeepAlivePeriod(p.config.Timeouts.DownstreamProxy.KeepAlivePeriod); err != nil {
			return fmt.Errorf("cannot set keep-alive period: %w", err)
		}
	}

	now := time.Now()
	if p.config.Timeouts.DownstreamProxy.ReadTimeout.Nanoseconds() != 0 {
		if err := pconn.SetReadDeadline(now.Add(p.config.Timeouts.DownstreamProxy.ReadTimeout)); err != nil {
			return fmt.Errorf("cannot set read timeout for connection with downstream proxy: %w", err)
		}
	}
	if p.config.Timeouts.DownstreamProxy.WriteTimeout.Nanoseconds() != 0 {
		if err := pconn.SetWriteDeadline(now.Add(p.config.Timeouts.DownstreamProxy.WriteTimeout)); err != nil {
			return fmt.Errorf("cannot set write timeout for connection with downstream proxy: %w", err)
		}
	}

	return nil
}

func (p *Proxy) Listen() (net.Listener, error) {
	p.logger.Info("Listening socket", zap.String("address", p.config.Addr.String()))

	l, err := net.Listen("tcp", p.config.Addr.String())
	if err != nil {
		p.logger.Error("Error while listening!", zap.Error(err))
		return nil, err
	}

	return l, nil
}

// Serve serves HTTP requests.
func (p *Proxy) Serve(l net.Listener) error {
	p.logger.Info("Serving HTTP requests", zap.String("address", p.config.Addr.String()))

	if err := p.server.Serve(l); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			p.logger.Error("Error while serving HTTP requests!", zap.Error(err))
			return err
		}
	}

	return nil
}

// Shutdown shuts down the HTTP server.
func (p *Proxy) Shutdown(ctx context.Context) error {
	if err := p.server.Shutdown(ctx); err != nil {
		p.logger.Error("Error shutting down HTTP server!", zap.Error(err))
		return err
	}

	return nil
}
