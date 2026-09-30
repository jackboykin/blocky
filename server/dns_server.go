package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/0xERR0R/blocky/util"
)

const (
	maxTCPQueries  = 128
	tcpReadTimeout = 2 * time.Second
	tcpIdleTimeout = 8 * time.Second

	acceptMinDelay = 5 * time.Millisecond
	acceptMaxDelay = time.Second
)

var (
	errServerNotStarted     = errors.New("server not started")
	errServerAlreadyStarted = errors.New("server already started")
)

// dnsServer serves TCP and TLS itself, one query at a time per connection: the dns package's
// server closes a connection while its replies are still being resolved.
type dnsServer struct {
	network string
	address string

	udp *dns.Server

	Listener  net.Listener
	tlsConfig *tls.Config

	handler func(dns.ResponseWriter, *dns.Msg)

	// dns.Server panics when started twice or shut down while not running
	mu      sync.Mutex
	serving bool
	running bool
	conns   map[net.Conn]struct{}
	connsWG sync.WaitGroup
}

func (s *dnsServer) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.running
}

func (s *dnsServer) notifyStarted() {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	logger().Infof("%s server is up and running on address %s", strings.ToUpper(s.network), s.address)
}

func (s *dnsServer) serve(ctx context.Context) error {
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()

		return errServerAlreadyStarted
	}

	s.serving = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.serving, s.running = false, false
		s.mu.Unlock()
	}()

	if s.udp != nil {
		return s.serveUDP()
	}

	return s.serveTCP(ctx)
}

func (s *dnsServer) serveUDP() error {
	s.udp.NotifyStartedFunc = func(context.Context) { s.notifyStarted() }
	s.udp.Handler = dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.handler(w, r)
		// serveDNS unpacked r into a message of its own
		s.udp.MsgPool.Put(r.Data)
	})

	return s.udp.ListenAndServe()
}

func (s *dnsServer) serveTCP(ctx context.Context) error {
	if s.Listener == nil {
		ln, err := (&net.ListenConfig{}).Listen(ctx, networkTCP, s.address)
		if err != nil {
			return err
		}

		if s.tlsConfig != nil {
			ln = tls.NewListener(ln, s.tlsConfig)
		}

		s.Listener = ln
	}

	s.mu.Lock()
	s.conns = make(map[net.Conn]struct{})
	s.mu.Unlock()

	s.notifyStarted()

	var delay time.Duration

	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			if !s.isRunning() || errors.Is(err, net.ErrClosed) {
				return nil
			}

			delay = min(max(2*delay, acceptMinDelay), acceptMaxDelay)
			logger().Warnf("%s accept failed, retrying in %s: %v", strings.ToUpper(s.network), delay, err)
			time.Sleep(delay)

			continue
		}

		delay = 0

		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.connsWG.Add(1)
		s.mu.Unlock()

		go s.serveTCPConn(conn)
	}
}

func (s *dnsServer) serveTCPConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()

		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()

		s.connsWG.Done()
	}()

	w := &tcpResponseWriter{conn}
	timeout := tcpReadTimeout

	for range maxTCPQueries {
		if !s.armRead(conn, timeout) {
			return
		}

		r, err := readTCPMsg(conn)
		if err != nil {
			return
		}

		if err := r.Unpack(); err == nil {
			if action := acceptMsg(r); action == dns.MsgAccept {
				s.handler(w, r)
			} else if reject(w, r, action) != nil {
				return
			}
		}

		timeout = tcpIdleTimeout
	}
}

// armRead holds the lock shutdown sets its past deadlines under, so it can't undo one.
func (s *dnsServer) armRead(conn net.Conn, timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.running && conn.SetReadDeadline(time.Now().Add(timeout)) == nil
}

func readTCPMsg(conn net.Conn) (*dns.Msg, error) {
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}

	r := &dns.Msg{Data: make([]byte, binary.BigEndian.Uint16(size[:]))}
	if _, err := io.ReadFull(conn, r.Data); err != nil {
		return nil, err
	}

	r.Options = dns.MsgOptionUnpackQuestion

	return r, nil
}

func reject(w dns.ResponseWriter, r *dns.Msg, action dns.MsgAcceptAction) error {
	var rcode uint16

	switch action {
	case dns.MsgAccept, dns.MsgIgnore:
		return nil
	case dns.MsgReject:
		rcode = dns.RcodeFormatError
	case dns.MsgRejectNotImplemented:
		rcode = dns.RcodeNotImplemented
	case dns.MsgRejectRefused:
		rcode = dns.RcodeRefused
	}

	resp := &dns.Msg{ID: r.ID, Opcode: r.Opcode, Response: true, Rcode: rcode}
	resp.Question = r.Question

	return dnsWriter{w}.WriteMsg(resp)
}

func (s *dnsServer) shutdown(ctx context.Context) error {
	s.mu.Lock()
	running := s.running
	s.running = false
	s.mu.Unlock()

	if !running {
		return errServerNotStarted
	}

	done := make(chan struct{})

	if s.udp != nil {
		go func() {
			// ignores ctx
			s.udp.Shutdown(ctx)
			close(done)
		}()
	} else {
		_ = s.Listener.Close()

		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.SetReadDeadline(time.Now())
		}
		s.mu.Unlock()

		go func() {
			s.connsWG.Wait()
			close(done)
		}()
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acceptMsg is the dns package's default without its refusal of RRSIG queries, and with limits
// on the other sections.
func acceptMsg(m *dns.Msg) dns.MsgAcceptAction {
	if m.Response {
		return dns.MsgIgnore
	}

	if m.Opcode != dns.OpcodeQuery && m.Opcode != dns.OpcodeNotify {
		return dns.MsgRejectNotImplemented
	}

	if len(m.Question) != 1 {
		return dns.MsgReject
	}

	// room for the SOA of a NOTIFY (RFC 1996) or IXFR (RFC 1995), and an OPT and a TSIG
	const (
		anCount = 6
		nsCount = 8
		arCount = 10
	)

	if binary.BigEndian.Uint16(m.Data[anCount:]) > 1 ||
		binary.BigEndian.Uint16(m.Data[nsCount:]) > 1 ||
		binary.BigEndian.Uint16(m.Data[arCount:]) > 2 {
		return dns.MsgReject
	}

	return dns.MsgAccept
}

// serveDNS gets r with only its question unpacked, in the server's buffer.
func (s *Server) serveDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	msg, err := util.UnpackMsg(r.Data)
	if err != nil {
		formErr := &dns.Msg{ID: r.ID, Opcode: r.Opcode, Response: true, Rcode: dns.RcodeFormatError}
		util.LogOnError(ctx, "can't write message: ", dnsWriter{w}.WriteMsg(formErr))

		return
	}

	if isHealthCheck(msg.Question[0]) {
		s.OnHealthCheck(ctx, w, msg)

		return
	}

	s.OnRequest(ctx, w, msg)
}

// isHealthCheck leaves DS queries to the parent zone.
func isHealthCheck(q dns.RR) bool {
	const zone = "healthcheck.blocky."

	name := util.LowerName(q.Header().Name)

	return dns.RRToType(q) != dns.TypeDS && (name == zone || strings.HasSuffix(name, "."+zone))
}

type dnsWriter struct {
	dns.ResponseWriter
}

func (w dnsWriter) WriteMsg(m *dns.Msg) error {
	buf, err := util.PackMsg(m)
	if err != nil {
		return err
	}

	_, err = (&dns.Msg{Data: buf}).WriteTo(w)

	return err
}

type tcpResponseWriter struct {
	conn net.Conn
}

func (w *tcpResponseWriter) LocalAddr() net.Addr         { return w.conn.LocalAddr() }
func (w *tcpResponseWriter) RemoteAddr() net.Addr        { return w.conn.RemoteAddr() }
func (w *tcpResponseWriter) Conn() net.Conn              { return w.conn }
func (w *tcpResponseWriter) Write(b []byte) (int, error) { return w.conn.Write(b) }
func (w *tcpResponseWriter) Close() error                { return w.conn.Close() }
func (w *tcpResponseWriter) Session() *dns.Session       { return nil }
func (w *tcpResponseWriter) Hijack()                     {}
