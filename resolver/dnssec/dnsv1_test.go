package dnssec

// Test side of the temporary v1 boundary (see dnsv1.go). Fixtures are v2; these helpers
// carry them across the boundary the way the resolver and upstream do.

import (
	"context"
	"crypto/ecdsa"
	"net"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	dnsv1 "github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// toV1 converts an upstream response fixture for a model.Response.
func toV1(m *dns.Msg) *dnsv1.Msg {
	GinkgoHelper()

	m1, err := msgToV1(m)
	Expect(err).Should(Succeed())

	return m1
}

// validateAsV1 validates v2 fixtures through the public v1 entry point.
func validateAsV1(ctx context.Context, v *Validator, response *dns.Msg, question dns.RR) ValidationResult {
	GinkgoHelper()

	q := dnsv1.Question{Name: question.Header().Name, Qtype: dns.RRToType(question), Qclass: question.Header().Class}

	return v.ValidateResponse(ctx, toV1(response), q)
}

// newQuestion returns the question for name and qtype in class IN.
func newQuestion(name string, qtype uint16) dns.RR {
	rr := dns.TypeToRR[qtype]()
	*rr.Header() = dns.Header{Name: name, Class: dns.ClassINET}

	return rr
}

var _ = Describe("v1 boundary", func() {
	var (
		ctx context.Context
		v   *Validator
	)

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx

		store, err := NewTrustAnchorStore(nil)
		Expect(err).Should(Succeed())

		logger, _ := log.NewMockEntry()
		upstream := &mockResolver{ResolveFn: func(context.Context, *model.Request) (*model.Response, error) {
			return &model.Response{Res: &dnsv1.Msg{Answer: []dnsv1.RR{unconvertibleA()}}}, nil
		}}
		v = NewValidator(ctx, store, logger, upstream, 1, 10, 150, 30, 3600)
	})

	It("treats a response it can't convert as Bogus", func() {
		// A forged unsigned answer under the root anchor is Bogus; appending a record v1
		// packs but v2 can't read must not turn that into a pass.
		forged := &dnsv1.A{
			Hdr: dnsv1.RR_Header{Name: "www.example.com.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
			A:   net.IPv4(6, 6, 6, 6),
		}
		hip := &dnsv1.RFC3597{
			Hdr:   dnsv1.RR_Header{Name: "www.example.com.", Rrtype: dnsv1.TypeHIP, Class: dnsv1.ClassINET, Ttl: 300},
			Rdata: "00",
		}
		response := &dnsv1.Msg{Answer: []dnsv1.RR{forged, hip}}
		question := dnsv1.Question{Name: "www.example.com.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET}

		_, err := response.Pack()
		Expect(err).Should(Succeed())
		_, err = responseToV2(response, question)
		Expect(err).Should(HaveOccurred())
		Expect(v.ValidateResponse(ctx, response, question)).Should(Equal(ValidationResultBogus))
	})

	It("treats a sub-query response it can't convert as unavailable", func() {
		ctx = context.WithValue(ctx, queryBudgetKey{}, 10)

		_, _, err := v.queryDNSKEY(ctx, "example.com.")
		Expect(err).Should(MatchError(errDNSKEYUnavailable))
	})

	DescribeTable("refuses a message v2 would read differently",
		func(m *dnsv1.Msg) {
			_, err := msgToV2(m)
			Expect(err).Should(MatchError(errLossyConversion))
		},
		Entry("dot in an owner label", &dnsv1.Msg{Answer: []dnsv1.RR{&dnsv1.A{
			Hdr: dnsv1.RR_Header{Name: "x\\.attacker.net.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		}}}),
		Entry("dot in an rdata label", &dnsv1.Msg{Ns: []dnsv1.RR{&dnsv1.NS{
			Hdr: dnsv1.RR_Header{Name: "attacker.net.", Rrtype: dnsv1.TypeNS, Class: dnsv1.ClassINET, Ttl: 300},
			Ns:  "ns\\.attacker.net.",
		}}}),
		Entry("dot in a question label", &dnsv1.Msg{Question: []dnsv1.Question{
			{Name: "x\\.attacker.net.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
		}}),
	)

	It("doesn't validate a record whose owner label holds a dot as the dotted name", func() {
		netKey, netPriv, netAnchor := newSignedZoneKey("net.")
		key, priv, anchor := newSignedZoneKey("attacker.net.")
		netKeySig := signRRset([]dns.RR{netKey}, dns.TypeDNSKEY, netKey, netPriv, "net.")
		keySig := signRRset([]dns.RR{key}, dns.TypeDNSKEY, key, priv, "attacker.net.")

		store, err := NewTrustAnchorStore([]string{netAnchor, anchor})
		Expect(err).Should(Succeed())

		logger, _ := log.NewMockEntry()
		upstream := &mockResolver{ResolveFn: func(_ context.Context, req *model.Request) (*model.Response, error) {
			q := req.Req.Question[0]
			switch {
			case q.Qtype == dns.TypeDNSKEY && q.Name == "net.":
				return &model.Response{Res: toV1(&dns.Msg{Answer: []dns.RR{netKey, netKeySig}})}, nil
			case q.Qtype == dns.TypeDNSKEY && q.Name == "attacker.net.":
				return &model.Response{Res: toV1(&dns.Msg{Answer: []dns.RR{key, keySig}})}, nil
			default:
				return &model.Response{Res: toV1(&dns.Msg{})}, nil
			}
		}}
		v := NewValidator(ctx, store, logger, upstream, 1, 10, 150, 30, 3600)

		// Signed as three labels, x.attacker.net., then answered as two, x\.attacker.net.
		a := &dns.A{Hdr: dns.Header{Name: "x.attacker.net.", Class: dns.ClassINET, TTL: 300}}
		a.Addr = netip.MustParseAddr("192.0.2.1")
		sig := signRRset([]dns.RR{a.Clone()}, dns.TypeA, key, priv, "attacker.net.")

		response := toV1(&dns.Msg{Answer: []dns.RR{a, sig}})
		for _, rr := range response.Answer {
			rr.Header().Name = "x\\.attacker.net."
		}
		question := dnsv1.Question{Name: "x\\.attacker.net.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET}

		Expect(v.ValidateResponse(ctx, response, question)).Should(Equal(ValidationResultBogus))
	})

	It("doesn't rewrite the extended rcode in the caller's OPT RR", func() {
		response := &dnsv1.Msg{}
		response.SetEdns0(1232, true)
		opt := response.IsEdns0()
		opt.SetExtendedRcode(dnsv1.RcodeBadVers)
		ttl := opt.Hdr.Ttl

		_, err := responseToV2(response, dnsv1.Question{Name: "example.com.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET})
		Expect(err).Should(Succeed())
		Expect(opt.Hdr.Ttl).Should(Equal(ttl))
	})

	It("validates the OPT RR in the additional section as an unsigned RRset", func() {
		// Nothing else here is an RRset; the unsigned OPT under the root trust anchor is Bogus.
		sig := &dnsv1.RRSIG{
			Hdr:         dnsv1.RR_Header{Name: "www.example.com.", Rrtype: dnsv1.TypeRRSIG, Class: dnsv1.ClassINET, Ttl: 300},
			TypeCovered: dnsv1.TypeA, Algorithm: dnsv1.ECDSAP256SHA256, Labels: 3, OrigTtl: 300,
			SignerName: "example.com.", Signature: "ZmFrZS1zaWduYXR1cmU=",
		}
		response := &dnsv1.Msg{Rcode: dnsv1.RcodeServerFailure, Extra: []dnsv1.RR{sig}}
		response.SetEdns0(1232, true)
		question := dnsv1.Question{Name: "www.example.com.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET}

		Expect(v.ValidateResponse(ctx, response, question)).Should(Equal(ValidationResultBogus))
	})
})

// unconvertibleA is a record v1 can't pack, as its address has five octets.
func unconvertibleA() dnsv1.RR {
	return &dnsv1.A{
		Hdr: dnsv1.RR_Header{Name: "example.com.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
		A:   net.IP{192, 0, 2, 1, 5},
	}
}

// Differential tests against v1 while it's still a dependency. Delete them with it.
var _ = Describe("agreement with v1", func() {
	It("hashes NSEC3 names as HashName does", func() {
		names := []string{
			".", "example.", "EXAMPLE.Com.", "example.com", "*.w.example.", "a.b.c.d.e.f.g.h.",
			"xn--bcher-kva.example.", "-_0.example.", strings.Repeat("a", 63) + ".example.",
			strings.Repeat(strings.Repeat("b", 63)+".", 4)[2:], // 255 octets
			strings.Repeat(strings.Repeat("b", 63)+".", 4),     // 257 octets
		}
		salts := []string{"", "00", "aabbccdd", "AABBCCDD", strings.Repeat("ff", 32), "abc", "zz"}

		for _, name := range names {
			for _, salt := range salts {
				for _, iterations := range []uint16{0, 1, 12, 150, 500} {
					want := dnsv1.HashName(dnsv1.Fqdn(strings.ToLower(name)), dnsv1.SHA1, iterations, salt)
					Expect(nsec3Hash(canonicalName(name), salt, iterations)).Should(Equal(want),
						"name %q salt %q iterations %d", name, salt, iterations)
				}
			}
		}
	})

	It("splits names and tests subdomains as SplitDomainName and IsSubDomain do", func() {
		// v1 names, with v1's escapes; v2 holds the escaped bytes as they are.
		names := []string{
			".", "", "com.", "example.com.", "www.example.com.", "WWW.Example.COM.", "example.com", "a.b.c.d.e.f.",
			`\200.example.com.`, `\200.`, `a\032b.example.com.`,
		}

		for _, a := range names {
			labels := dnsv1.SplitDomainName(a)
			for i, l := range labels {
				labels[i] = strings.TrimSuffix(unescapeV1(l+"."), ".")
			}

			Expect(splitName(unescapeV1(a))).Should(Equal(labels), "split %q", a)

			if a == "" {
				continue
			}

			for _, b := range names {
				if dnsutil.IsFqdn(b) { // isSubDomain's callers only pass qualified children
					Expect(isSubDomain(unescapeV1(a), unescapeV1(b))).Should(Equal(dnsv1.IsSubDomain(a, b)),
						"isSubDomain(%q, %q)", a, b)
				}
			}
		}
	})

	It("refuses names v2 can't split as v1 does", func() {
		for _, name := range []string{`a\.b.`, `a\046b.example.com.`} {
			_, err := msgToV2(&dnsv1.Msg{Question: []dnsv1.Question{{Name: name, Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET}}})
			Expect(err).Should(MatchError(errLossyConversion), name)
		}
	})

	It("hashes names with bytes that aren't UTF-8 as HashName does", func(ctx SpecContext) {
		logger, _ := log.NewMockEntry()
		v := NewValidator(ctx, dummyAnchorStore(), logger, &mockResolver{}, 1, 10, 150, 30, 3600)

		fe, err := v.computeNSEC3Hash("\xfe.example.", dns.SHA1, "aabbccdd", 12)
		Expect(err).Should(Succeed())
		ff, err := v.computeNSEC3Hash("\xff.EXAMPLE.", dns.SHA1, "aabbccdd", 12)
		Expect(err).Should(Succeed())

		Expect(fe).ShouldNot(Equal(ff))
		Expect(fe).Should(Equal(dnsv1.HashName(`\254.example.`, dnsv1.SHA1, 12, "aabbccdd")))
		Expect(ff).Should(Equal(dnsv1.HashName(`\255.example.`, dnsv1.SHA1, 12, "aabbccdd")))
	})

	DescribeTable("verifies RRsets v1 signed and verifies",
		func(records ...string) {
			key, sig, rrset := signV1(records...)

			m, err := msgToV2(&dnsv1.Msg{Answer: append(rrset, sig, key)})
			Expect(err).Should(Succeed())

			n := len(rrset)
			Expect(verifySignature(m.Answer[n].(*dns.RRSIG), m.Answer[n+1].(*dns.DNSKEY), m.Answer[:n])).Should(Succeed())
		},
		Entry("CAA values of different lengths",
			`example.com. 3600 IN CAA 0 issue "pki.goog"`, `example.com. 3600 IN CAA 0 issue "letsencrypt.org"`),
		Entry("TXT records with different string counts",
			`example.com. 3600 IN TXT "v=spf1 -all"`, `example.com. 3600 IN TXT "part1" "part2"`),
		Entry("duplicate records", "example.com. 3600 IN A 192.0.2.1", "example.com. 3600 IN A 192.0.2.1"),
		Entry("uppercase names in rdata", "example.com. 3600 IN NS NS1.Example.COM.", "example.com. 3600 IN NS ns2.example.com."),
		Entry("an SOA", "example.com. 3600 IN SOA NS.Example.com. Hostmaster.Example.com. 1 7200 3600 1209600 300"),
		Entry("MX records", "example.com. 3600 IN MX 10 b.example.com.", "example.com. 3600 IN MX 10 aa.example.com."),
		Entry("an uppercase owner", "WWW.Example.com. 3600 IN A 192.0.2.1"),
	)

	It("verifies a wildcard expansion as v1 does", func() {
		key, sig, rrset := signV1("*.example.com. 3600 IN A 192.0.2.1")
		rrset[0].Header().Name = "www.example.com."
		sig.Hdr.Name = "www.example.com."
		Expect(sig.Verify(key, rrset)).Should(Succeed())

		m, err := msgToV2(&dnsv1.Msg{Answer: []dnsv1.RR{rrset[0], sig, key}})
		Expect(err).Should(Succeed())
		Expect(verifySignature(m.Answer[1].(*dns.RRSIG), m.Answer[2].(*dns.DNSKEY), m.Answer[:1])).Should(Succeed())
	})
})

// signV1 signs the records, one RRset in presentation format, with a new v1 zone key for
// example.com, and checks v1 verifies them.
func signV1(records ...string) (*dnsv1.DNSKEY, *dnsv1.RRSIG, []dnsv1.RR) {
	GinkgoHelper()

	key := &dnsv1.DNSKEY{
		Hdr:   dnsv1.RR_Header{Name: "example.com.", Rrtype: dnsv1.TypeDNSKEY, Class: dnsv1.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dnsv1.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	Expect(err).Should(Succeed())

	rrset := make([]dnsv1.RR, len(records))
	for i, s := range records {
		rrset[i], err = dnsv1.NewRR(s)
		Expect(err).Should(Succeed())
	}

	sig := &dnsv1.RRSIG{
		Hdr:       dnsv1.RR_Header{Ttl: 3600},
		Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: "example.com.",
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix()),
	}
	Expect(sig.Sign(priv.(*ecdsa.PrivateKey), rrset)).Should(Succeed())
	Expect(sig.Verify(key, rrset)).Should(Succeed())

	return key, sig, rrset
}

// unescapeV1 returns the v2 form of the v1 name: its escapes resolved to the bytes they
// stand for. Names without escapes are the same in both.
func unescapeV1(name string) string {
	if !strings.Contains(name, `\`) {
		return name
	}

	wire := nameWire(name)
	Expect(wire).ShouldNot(BeNil())

	var b strings.Builder
	for i := 0; wire[i] != 0; i += int(wire[i]) + 1 {
		b.Write(wire[i+1 : i+1+int(wire[i])])
		b.WriteByte('.')
	}

	return b.String()
}
