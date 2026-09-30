package util

import (
	"bytes"
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Message helpers", func() {
	// answers returns n A records with distinct owner names, so compression can't shrink
	// them to nothing and each one adds to the packed size.
	answers := func(n int) []dns.RR {
		rrs := make([]dns.RR, n)
		for i := range rrs {
			rrs[i] = &dns.A{
				Hdr:  dns.Header{Name: fmt.Sprintf("host%d.example.com.", i), Class: dns.ClassINET, TTL: 300},
				Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}),
			}
		}

		return rrs
	}

	packedLen := func(m *dns.Msg) int {
		buf, err := PackMsg(m)
		Expect(err).Should(Succeed())

		return len(buf)
	}

	Describe("Truncate", func() {
		It("leaves a message that fits alone", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(3)

			Truncate(m, dns.MinMsgSize)

			Expect(m.Answer).Should(HaveLen(3))
			Expect(m.Truncated).Should(BeFalse())
		})

		It("keeps the longest run of records that fits and sets TC", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(40) // too many to fit on their own
			m.Ns = answers(5)
			m.Extra = answers(5)
			all := m.Answer

			Truncate(m, dns.MinMsgSize)

			Expect(m.Truncated).Should(BeTrue())
			Expect(packedLen(m)).Should(BeNumerically("<=", dns.MinMsgSize))
			Expect(m.Answer).ShouldNot(BeEmpty())
			Expect(all[:len(m.Answer)]).Should(Equal(m.Answer), "a prefix of the answer section")
			Expect(m.Ns).Should(BeEmpty())
			Expect(m.Extra).Should(BeEmpty())

			// one record more wouldn't fit
			m.Answer = all[:len(m.Answer)+1]
			Expect(packedLen(m)).Should(BeNumerically(">", dns.MinMsgSize))
		})

		It("keeps records that only fit compressed", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(20)
			for _, rr := range m.Answer {
				rr.Header().Name = "a-rather-long-owner-name-that-compresses-well.example.com."
			}

			Expect(m.Len()).Should(BeNumerically(">", dns.MinMsgSize), "the scenario: too long uncompressed")
			Expect(packedLen(m)).Should(BeNumerically("<=", dns.MinMsgSize), "the scenario: fits compressed")

			Truncate(m, dns.MinMsgSize)

			Expect(m.Answer).Should(HaveLen(20))
			Expect(m.Truncated).Should(BeFalse())
		})

		It("counts a size below 512 as 512", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(3)

			Truncate(m, 100)

			Expect(m.Answer).Should(HaveLen(3))
		})
	})

	Describe("PackMsg", func() {
		It("doesn't write into the message's wire data", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Data = make([]byte, 0, 512)
			m.Data = append(m.Data, "sentinel"...)

			buf, err := PackMsg(m)
			Expect(err).Should(Succeed())

			Expect(string(m.Data)).Should(Equal("sentinel"))
			Expect(string(m.Data[:cap(m.Data)][:8])).Should(Equal("sentinel"))
			Expect(buf).ShouldNot(BeEmpty())
		})

		It("packs the message as it is", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(2)

			buf, err := PackMsg(m)
			Expect(err).Should(Succeed())

			back, err := UnpackMsg(buf)
			Expect(err).Should(Succeed())
			Expect(back.ID).Should(Equal(m.ID))
			Expect(back.Answer).Should(HaveLen(2))
		})
	})

	Describe("UnpackMsg", func() {
		It("doesn't keep the buffer", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(2)
			buf, err := PackMsg(m)
			Expect(err).Should(Succeed())
			orig := bytes.Clone(buf)

			res, err := UnpackMsg(buf)
			Expect(err).Should(Succeed())
			Expect(res.Data).Should(BeNil())

			res.ID++
			Expect(res.Pack()).Should(Succeed())
			Expect(buf).Should(Equal(orig))
		})
	})

	Describe("CloneMsg", func() {
		It("shares nothing with the original", func() {
			m := NewMsgWithQuestion(exampleDomain, dns.TypeA)
			m.Answer = answers(1)
			m.Pseudo = []dns.RR{new(dns.COOKIE)}
			m.Data = []byte("stale")

			c := CloneMsg(m)

			Expect(c.ID).Should(Equal(m.ID))
			Expect(c.Data).Should(BeNil())

			c.Question[0].Header().Name = "other."
			c.Answer[0].Header().TTL = 1
			c.Answer = append(c.Answer, answers(1)...)
			c.Pseudo[0] = new(dns.EDE)

			Expect(m.Question[0].Header().Name).Should(Equal(exampleDomain + "."))
			Expect(m.Answer).Should(HaveLen(1))
			Expect(m.Answer[0].Header().TTL).Should(BeNumerically("==", 300))
			Expect(m.Pseudo[0]).Should(BeAssignableToTypeOf(new(dns.COOKIE)))
		})
	})
})
