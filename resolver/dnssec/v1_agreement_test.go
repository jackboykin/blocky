package dnssec

// Differential tests against github.com/miekg/dns (v1) while it's still a dependency. Delete
// this file with it.

import (
	"crypto/ecdsa"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
	dnsv1 "github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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

			m, err := util.MsgFromV1(&dnsv1.Msg{Answer: append(rrset, sig, key)})
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

		m, err := util.MsgFromV1(&dnsv1.Msg{Answer: []dnsv1.RR{rrset[0], sig, key}})
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

	wire := make([]byte, 255)
	n, err := dnsv1.PackDomainName(name, wire, 0, nil, false)
	Expect(err).Should(Succeed())
	wire = wire[:n]

	var b strings.Builder
	for i := 0; wire[i] != 0; i += int(wire[i]) + 1 {
		b.Write(wire[i+1 : i+1+int(wire[i])])
		b.WriteByte('.')
	}

	return b.String()
}
