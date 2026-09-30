package server

import (
	"context"

	"codeberg.org/miekg/dns"
	dnsv1 "github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// capturingWriter records what the v1 bridge writes. Only the methods it uses are implemented.
type capturingWriter struct {
	dnsv1.ResponseWriter

	msg *dnsv1.Msg
}

func (w *capturingWriter) WriteMsg(m *dnsv1.Msg) error {
	w.msg = m

	return nil
}

var _ = Describe("v1 server bridge", func() {
	It("answers a request v2 can't read with FORMERR without handling it", func(ctx context.Context) {
		req := new(dnsv1.Msg)
		req.SetQuestion("example.com.", dnsv1.TypeA)
		// RFC 6891 section 6.1.1: more than one OPT RR is a FORMERR
		req.SetEdns0(1232, false)
		req.Extra = append(req.Extra, &dnsv1.OPT{Hdr: dnsv1.RR_Header{Name: ".", Rrtype: dnsv1.TypeOPT}})

		handled := false
		w := &capturingWriter{}

		v1Handler(ctx, func(context.Context, dnsv1.ResponseWriter, *dns.Msg) { handled = true })(w, req)

		Expect(handled).Should(BeFalse())
		Expect(w.msg).ShouldNot(BeNil())
		Expect(w.msg.Rcode).Should(Equal(dnsv1.RcodeFormatError))
		Expect(w.msg.Id).Should(Equal(req.Id))
	})
})
