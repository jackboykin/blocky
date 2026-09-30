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

// TCP connection limits, as github.com/miekg/dns v1 had them.
const (
	maxTCPQueries  = 128             // queries served on a connection before it is closed
	tcpReadTimeout = 2 * time.Second // for the first query on a connection
	tcpIdleTimeout = 8 * time.Second // for the queries after it (RFC 7766 section 6.2.3)

	acceptMinDelay = 5 * time.Millisecond // backoff after a failed accept
	acceptMaxDelay = time.Second
)

var (
	errServerNotStarted     = errors.New("server not started")
	errServerAlreadyStarted = errors.New("server already started")
)

// dnsServer serves DNS on one address. UDP is served by codeberg.org/miekg/dns, TCP and TLS by
// blocky itself, one query at a time per connection, as github.com/miekg/dns v1 did: the v2
// server answers a connection's queries concurrently and closes the connection as soon as it
// stops reading, dropping the replies still being resolved.
type dnsServer struct {
	network string // "udp", "tcp" or "tcp-tls"
	address string

	udp *dns.Server // UDP only

	// TCP and TLS only. Listener may be created up front (freebind, PROXY protocol).
	Listener  net.Listener
	tlsConfig *tls.Config

	handler func(dns.ResponseWriter, *dns.Msg)

	// A dns.Server panics when it is started twice or shut down while it isn't running, so the
	// state is tracked here for both kinds.
	mu      sync.Mutex
	serving bool // serve was called and hasn't returned
	running bool // listening
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

// serve listens and serves until the server is shut down.
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
		// the request was unpacked into a message of its own, see Server.serveDNS
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

			// Out of file descriptors, for instance: wait for connections to close, as net/http does.
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

// armRead sets the deadline for the next read on conn, unless the server is shutting down. It
// holds the lock shutdown sets its past deadlines under, so it can't undo one.
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

	// the question is all acceptMsg needs, see Server.serveDNS for the rest
	r.Options = dns.MsgOptionUnpackQuestion

	return r, nil
}

// reject answers a request acceptMsg didn't accept, like the dns package's server does.
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

// shutdown stops listening and waits for the requests in flight, as long as ctx allows.
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
		// Shutdown waits for the requests in flight, and ignores ctx
		go func() {
			s.udp.Shutdown(ctx)
			close(done)
		}()
	} else {
		_ = s.Listener.Close()

		// unblock the connections waiting for their next query
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

// acceptMsg filters requests the way github.com/miekg/dns v1's default did. v2's default also
// refuses RRSIG queries and has no limits on the other sections.
func acceptMsg(m *dns.Msg) dns.MsgAcceptAction {
	if m.Response {
		return dns.MsgIgnore
	}

	// Dynamic updates are refused, because their sections can hold any number of RRs.
	if m.Opcode != dns.OpcodeQuery && m.Opcode != dns.OpcodeNotify {
		return dns.MsgRejectNotImplemented
	}

	if len(m.Question) != 1 {
		return dns.MsgReject
	}

	// Only the question is unpacked at this point, so the other counts come from the header. A
	// NOTIFY may carry an SOA in the answer section (RFC 1996), an IXFR one in the authority
	// section (RFC 1995), and the additional section an OPT and a TSIG.
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

// serveDNS answers an accepted request, of which only the question is unpacked. It is unpacked
// again, fully and into a message that doesn't hold the server's buffer.
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

// isHealthCheck reports whether q is for the health check zone, which DS queries aren't: they
// belong to the parent zone.
func isHealthCheck(q dns.RR) bool {
	const zone = "healthcheck.blocky."

	name := strings.ToLower(q.Header().Name)

	return dns.RRToType(q) != dns.TypeDS && (name == zone || strings.HasSuffix(name, "."+zone))
}

// dnsWriter writes messages to a dns.ResponseWriter, packed into a buffer of their own.
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

// tcpResponseWriter is the dns.ResponseWriter of a TCP or TLS connection. Msg.WriteTo frames
// what it writes.
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
