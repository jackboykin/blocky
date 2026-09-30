package server

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// failingListener fails its first Accept, like a process out of file descriptors.
type failingListener struct {
	net.Listener

	failed atomic.Bool
}

func (l *failingListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, &net.OpError{Op: "accept", Net: networkTCP, Err: syscall.EMFILE}
	}

	return l.Listener.Accept()
}

var _ = Describe("TCP DNS server", func() {
	var (
		srv          *dnsServer
		addr         string
		handlerDelay time.Duration
	)

	BeforeEach(func(ctx SpecContext) {
		var err error

		srv, err = createTCPServer(ctx, "127.0.0.1:0", listenerOptions{})
		Expect(err).Should(Succeed())

		// pre-create the listener to learn its address
		ln, err := net.Listen(networkTCP, "127.0.0.1:0")
		Expect(err).Should(Succeed())
		srv.Listener = &failingListener{Listener: ln}
		addr = ln.Addr().String()

		// slow enough that a server closing the connection early loses the reply
		handlerDelay = 5 * time.Millisecond
		srv.handler = func(w dns.ResponseWriter, r *dns.Msg) {
			time.Sleep(handlerDelay)

			req, err := util.UnpackMsg(r.Data)
			Expect(err).Should(Succeed())
			_ = dnsWriter{w}.WriteMsg(model.SetReply(new(dns.Msg), req))
		}

		go func() {
			defer GinkgoRecover()
			Expect(srv.serve(context.Background())).Should(Succeed())
		}()
		Eventually(srv.isRunning).Should(BeTrue())

		DeferCleanup(func(ctx context.Context) { _ = srv.shutdown(ctx) })
	})

	dial := func(ctx context.Context) *net.TCPConn {
		conn, err := (&net.Dialer{}).DialContext(ctx, networkTCP, addr)
		Expect(err).Should(Succeed())
		DeferCleanup(conn.Close)

		return conn.(*net.TCPConn)
	}

	send := func(conn net.Conn, query *dns.Msg) {
		buf, err := util.PackMsg(query)
		Expect(err).Should(Succeed())

		_, err = conn.Write(append([]byte{byte(len(buf) >> 8), byte(len(buf))}, buf...))
		Expect(err).Should(Succeed())
	}

	receive := func(conn net.Conn) (*dns.Msg, error) {
		resp := &dns.Msg{Data: make([]byte, dns.MinMsgSize)}
		if _, err := resp.ReadFrom(conn); err != nil {
			return nil, err
		}

		return resp, resp.Unpack()
	}

	It("keeps serving after a failed accept, such as one out of file descriptors", func(ctx SpecContext) {
		// the listener failed its first accept already, at start
		_, _, err := dns.NewClient().ExchangeWithConn(ctx, util.NewMsgWithQuestion("example.com.", A), dial(ctx))
		Expect(err).Should(Succeed())
	})

	It("answers every query of a connection before closing it", func(ctx SpecContext) {
		conn := dial(ctx)
		client := dns.NewClient()

		for i := range maxTCPQueries {
			_, _, err := client.ExchangeWithConn(ctx, util.NewMsgWithQuestion("example.com.", A), conn)
			Expect(err).Should(Succeed(), "query %d", i+1)
		}
	})

	It("answers a query the client stopped writing after", func(ctx SpecContext) {
		conn := dial(ctx)

		query := util.NewMsgWithQuestion("example.com.", A)
		send(conn, query)
		Expect(conn.CloseWrite()).Should(Succeed())

		resp, err := receive(conn)
		Expect(err).Should(Succeed())
		Expect(resp.ID).Should(Equal(query.ID))
	})

	It("answers the query in flight on shutdown, and no more", func(ctx SpecContext) {
		handlerDelay = 300 * time.Millisecond
		conn := dial(ctx)

		first := util.NewMsgWithQuestion("example.com.", A)
		send(conn, first)
		time.Sleep(50 * time.Millisecond) // the handler is busy with it

		shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		DeferCleanup(cancel)

		start := time.Now()
		done := make(chan error, 1)
		go func() { done <- srv.shutdown(shutdownCtx) }()

		send(conn, util.NewMsgWithQuestion("example.org.", A))

		resp, err := receive(conn)
		Expect(err).Should(Succeed())
		Expect(resp.ID).Should(Equal(first.ID))

		Eventually(done).Should(Receive(Succeed()))
		Expect(time.Since(start)).Should(BeNumerically("<", time.Second))

		_, err = receive(conn)
		Expect(err).Should(HaveOccurred(), "the connection is closed without a second answer")
	})
})
