package dnssec

import (
	"codeberg.org/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("verifySignature", func() {
	var (
		key   *dns.DNSKEY
		rrset []dns.RR
		sig   *dns.RRSIG
	)

	BeforeEach(func() {
		k, priv, _ := newSignedZoneKey("example.com.")
		key = k

		// Out of canonical order, with uppercase names: what verifying rewrites in place.
		rrset = []dns.RR{
			&dns.NS{Hdr: dns.Header{Name: "Example.COM.", Class: dns.ClassINET, TTL: 3600}, Ns: "NS2.Example.COM."},
			&dns.NS{Hdr: dns.Header{Name: "Example.COM.", Class: dns.ClassINET, TTL: 3600}, Ns: "NS1.Example.COM."},
		}

		signed := make([]dns.RR, len(rrset)) // Sign rewrites its rrset too
		for i, rr := range rrset {
			signed[i] = rr.Clone()
		}

		sig = signRRset(signed, dns.TypeNS, key, priv, "example.com.")
		// Names match case-insensitively; Verify would rewrite both.
		sig.Hdr.Name = "example.com."
		sig.SignerName = "EXAMPLE.com."
	})

	It("verifies without changing the records or the RRSIG", func() {
		before := make([]string, len(rrset))
		for i, rr := range rrset {
			before[i] = rr.String()
		}
		sigBefore := sig.String()

		Expect(verifySignature(sig, key, rrset)).Should(Succeed())

		for i, rr := range rrset {
			Expect(rr.String()).Should(Equal(before[i]))
		}
		Expect(sig.String()).Should(Equal(sigBefore))
	})

	It("rejects an RRSIG owned by another name", func() {
		sig.Hdr.Name = "other.example.com."

		Expect(verifySignature(sig, key, rrset)).Should(MatchError(errRRset))
	})

	It("rejects an RRSIG that covers another type", func() {
		sig.TypeCovered = dns.TypeA

		Expect(verifySignature(sig, key, rrset)).Should(MatchError(errRRset))
	})

	It("rejects records that aren't one RRset", func() {
		other := &dns.NS{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 3600}, Ns: "ns1.example.com."}

		Expect(verifySignature(sig, key, append(rrset, other))).Should(MatchError(errRRset))
	})

	It("rejects a key that isn't the signer's", func() {
		sig.SignerName = "other.com."

		Expect(verifySignature(sig, key, rrset)).Should(MatchError(dns.ErrKey))
	})
})
