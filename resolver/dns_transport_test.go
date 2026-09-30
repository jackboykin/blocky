package resolver

import (
	"context"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("dnsTransport", func() {
	var (
		upstream *net.UDPConn
		query    *dns.Msg
		sut      *dnsTransport
	)

	BeforeEach(func() {
		var err error

		upstream, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		Expect(err).Should(Succeed())
		DeferCleanup(upstream.Close)

		query = util.NewMsgWithQuestion("example.com.", A)
		sut = &dnsTransport{Net: transportUDP}
	})

	// reply answers the next query with a reply to it, after sending the replies with other IDs.
	reply := func(otherIDs ...uint16) {
		go func() {
			defer GinkgoRecover()

			buf := make([]byte, dns.MinMsgSize)
			n, client, err := upstream.ReadFromUDP(buf)
			Expect(err).Should(Succeed())

			req, err := util.UnpackMsg(buf[:n])
			Expect(err).Should(Succeed())

			resp := model.SetReply(new(dns.Msg), req)

			for _, id := range append(otherIDs, req.ID) {
				resp.ID = id
				out, err := util.PackMsg(resp)
				Expect(err).Should(Succeed())

				_, err = upstream.WriteToUDP(out, client)
				Expect(err).Should(Succeed())
			}
		}()
	}

	It("skips UDP replies with another ID", func(ctx SpecContext) {
		reply(query.ID+1, query.ID+2)

		resp, _, err := sut.exchange(ctx, query, upstream.LocalAddr().String())
		Expect(err).Should(Succeed())
		Expect(resp.ID).Should(Equal(query.ID))
	})

	It("leaves the query as it is, as it may be shared", func(ctx SpecContext) {
		reply()

		_, _, err := sut.exchange(ctx, query, upstream.LocalAddr().String())
		Expect(err).Should(Succeed())
		Expect(query.Data).Should(BeNil())
	})

	It("stops waiting for the reply when the context is cancelled", func(ctx SpecContext) {
		cctx, cancel := context.WithCancel(ctx)
		time.AfterFunc(50*time.Millisecond, cancel)

		start := time.Now()
		_, _, err := sut.exchange(cctx, query, upstream.LocalAddr().String())

		Expect(err).Should(HaveOccurred())
		Expect(time.Since(start)).Should(BeNumerically("<", dnsTimeout/2))
	})

	It("fails a TCP reply with another ID", func(ctx SpecContext) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).Should(Succeed())
		DeferCleanup(ln.Close)

		go func() {
			defer GinkgoRecover()

			conn, err := ln.Accept()
			Expect(err).Should(Succeed())
			defer conn.Close()

			req, err := readMsg(conn, false, 0)
			Expect(err).Should(Succeed())

			resp := model.SetReply(new(dns.Msg), req)
			resp.ID++
			out, err := util.PackMsg(resp)
			Expect(err).Should(Succeed())
			Expect(writeMsg(conn, out, false)).Should(Succeed())
		}()

		_, _, err = (&dnsTransport{Net: transportTCP}).exchange(ctx, query, ln.Addr().String())
		Expect(err).Should(MatchError(errDNSIDMismatch))
	})
})
