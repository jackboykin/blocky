package util

import (
	"net"
	"net/netip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IP conversion", func() {
	Describe("ParseIP", func() {
		It("unmaps IPv4-mapped IPv6 addresses", func() {
			Expect(ParseIP("::ffff:192.0.2.1")).Should(Equal(netip.MustParseAddr("192.0.2.1")))
		})

		It("rejects what net.ParseIP rejects", func() {
			Expect(ParseIP("fe80::1%eth0").IsValid()).Should(BeFalse())
			Expect(ParseIP("example.com").IsValid()).Should(BeFalse())
			Expect(ParseIP("").IsValid()).Should(BeFalse())
		})
	})

	Describe("ParsePrefix", func() {
		DescribeTable("matches net.ParseCIDR",
			func(in, want string) {
				Expect(ParsePrefix(in)).Should(Equal(netip.MustParsePrefix(want)))
			},
			Entry("masks host bits", "10.43.8.67/28", "10.43.8.64/28"),
			Entry("unmaps an IPv4-mapped prefix", "::ffff:10.0.0.0/104", "10.0.0.0/8"),
			Entry("accepts a leading-zero length", "10.1.0.0/08", "10.0.0.0/8"),
			Entry("keeps IPv6", "2001:db8::1/32", "2001:db8::/32"),
		)

		It("rejects what net.ParseCIDR rejects", func() {
			_, err := ParsePrefix("10.0.0.1")
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("AddrFromIP", func() {
		It("unmaps the 16-byte IPv4 form", func() {
			Expect(AddrFromIP(net.ParseIP("192.0.2.1"))).Should(Equal(netip.MustParseAddr("192.0.2.1")))
		})

		It("returns the zero Addr for nil", func() {
			Expect(AddrFromIP(nil).IsValid()).Should(BeFalse())
		})
	})

	Describe("IPFromAddr", func() {
		It("returns nil for the zero Addr", func() {
			Expect(IPFromAddr(netip.Addr{})).Should(BeNil())
		})

		It("matches net.ParseIP byte for byte", func() {
			for _, s := range []string{"192.0.2.1", "2001:db8::1"} {
				Expect(IPFromAddr(netip.MustParseAddr(s))).Should(Equal(net.ParseIP(s)))
			}
		})
	})
})
