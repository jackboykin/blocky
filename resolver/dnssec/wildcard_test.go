package dnssec

import (
	"github.com/0xERR0R/blocky/log"
	dnsv1 "github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Wildcard validation functions", func() {
	var (
		sut          *Validator
		trustStore   *TrustAnchorStore
		mockUpstream *mockResolver
	)

	BeforeEach(func(specCtx SpecContext) {
		var err error
		trustStore, err = NewTrustAnchorStore(nil)
		Expect(err).Should(Succeed())

		mockUpstream = &mockResolver{}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(specCtx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
	})

	Describe("validateWildcardExpansion", func() {
		It("should pass when not a wildcard (same label count)", func() {
			rrsig := &dnsv1.RRSIG{
				Labels:     2, // example.com
				SignerName: "example.com.",
			}

			err := sut.validateWildcardExpansion("example.com.", rrsig, nil, "example.com.")
			Expect(err).Should(Succeed())
		})

		It("should pass when not a wildcard (fewer labels)", func() {
			rrsig := &dnsv1.RRSIG{
				Labels:     3, // sub.example.com
				SignerName: "example.com.",
			}

			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, nil, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should validate wildcard when RRset has more labels than RRSIG", func() {
			rrsig := &dnsv1.RRSIG{
				Labels:     2, // *.example.com -> 2 labels after wildcard
				SignerName: "example.com.",
			}

			// RRset has 3 labels, RRSIG says 2 -> wildcard expansion
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dnsv1.RR{nsec}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should fail when wildcard name not within signer zone", func() {
			rrsig := &dnsv1.RRSIG{
				Labels:     2,
				SignerName: "other.com.", // Different zone
			}

			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dnsv1.RR{nsec}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("not within signer zone"))
		})

		It("should accept wildcard when no NSEC/NSEC3 proof provided (positive response)", func() {
			rrsig := &dnsv1.RRSIG{
				Labels:     2,
				SignerName: "example.com.",
			}

			// No NSEC/NSEC3 records in authority section
			// For positive responses, the cryptographic signature is sufficient proof
			err := sut.validateWildcardExpansion("sub.example.com.", rrsig, []dnsv1.RR{}, "sub.example.com.")
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should handle deeply nested wildcards", func() {
			rrsig := &dnsv1.RRSIG{
				Labels:     3, // *.sub.example.com
				SignerName: "example.com.",
			}

			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.sub.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.sub.example.com.",
			}

			err := sut.validateWildcardExpansion("test.sub.example.com.", rrsig, []dnsv1.RR{nsec}, "test.sub.example.com.")
			Expect(err).Should(Succeed())
		})
	})

	Describe("validateWildcardNSEC", func() {
		It("should validate when NSEC covers query name", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardNSEC([]*dnsv1.NSEC{nsec}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should fail when no NSEC covers query name", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "b.example.com.",
			}

			err := sut.validateWildcardNSEC([]*dnsv1.NSEC{nsec}, "z.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC record covers"))
		})

		It("should handle empty NSEC list", func() {
			err := sut.validateWildcardNSEC([]*dnsv1.NSEC{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
		})

		It("should normalize domain names", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardNSEC([]*dnsv1.NSEC{nsec}, "sub.example.com")
			Expect(err).Should(Succeed())
		})

		It("should check multiple NSEC records", func() {
			nsec1 := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "m.example.com.",
			}
			nsec2 := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "m.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			// Query covered by second NSEC
			err := sut.validateWildcardNSEC([]*dnsv1.NSEC{nsec1, nsec2}, "n.example.com.")
			Expect(err).Should(Succeed())
		})
	})

	Describe("validateWildcardNSEC3", func() {
		It("should fail when no NSEC3 records provided", func() {
			err := sut.validateWildcardNSEC3([]*dnsv1.NSEC3{}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no NSEC3 records"))
		})

		It("should fail when NSEC3 parameters inconsistent", func() {
			nsec3_1 := &dnsv1.NSEC3{
				Hdr:        dnsv1.RR_Header{Name: "abc123.example.com.", Rrtype: dnsv1.TypeNSEC3},
				Hash:       dnsv1.SHA1,
				Salt:       "aabbcc",
				Iterations: 10,
			}
			nsec3_2 := &dnsv1.NSEC3{
				Hdr:        dnsv1.RR_Header{Name: "def456.example.com.", Rrtype: dnsv1.TypeNSEC3},
				Hash:       dnsv1.SHA1,
				Salt:       "ddeeff", // Different salt
				Iterations: 10,
			}

			err := sut.validateWildcardNSEC3([]*dnsv1.NSEC3{nsec3_1, nsec3_2}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("inconsistent"))
		})

		It("should fail when iteration count exceeds maximum", func() {
			nsec3 := &dnsv1.NSEC3{
				Hdr:        dnsv1.RR_Header{Name: "abc123.example.com.", Rrtype: dnsv1.TypeNSEC3},
				Hash:       dnsv1.SHA1,
				Salt:       "aabbcc",
				Iterations: 10000, // Way over the limit
			}

			err := sut.validateWildcardNSEC3([]*dnsv1.NSEC3{nsec3}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("exceeds maximum"))
		})

		It("should fail for unsupported hash algorithm", func() {
			nsec3 := &dnsv1.NSEC3{
				Hdr:        dnsv1.RR_Header{Name: "abc123.example.com.", Rrtype: dnsv1.TypeNSEC3},
				Hash:       2, // Not SHA1
				Salt:       "aabbcc",
				Iterations: 10,
			}

			err := sut.validateWildcardNSEC3([]*dnsv1.NSEC3{nsec3}, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("unsupported"))
		})

		It("should normalize domain names", func() {
			nsec3 := &dnsv1.NSEC3{
				Hdr:        dnsv1.RR_Header{Name: "abc123.example.com.", Rrtype: dnsv1.TypeNSEC3},
				Hash:       dnsv1.SHA1,
				Salt:       "",
				Iterations: 0,
				NextDomain: "zzz999",
			}

			// Will fail because hash won't match, but validates inputs
			err := sut.validateWildcardNSEC3([]*dnsv1.NSEC3{nsec3}, "sub.example.com")
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("validateWildcardProof", func() {
		It("should use NSEC when available", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dnsv1.RR{nsec}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should accept wildcard when neither NSEC nor NSEC3 available (positive response)", func() {
			// For positive responses, the cryptographic signature is sufficient proof
			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dnsv1.RR{}, "sub.example.com.")
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should accept wildcard with non-NSEC/NSEC3 records (positive response)", func() {
			otherRR := &dnsv1.A{
				Hdr: dnsv1.RR_Header{Name: "example.com.", Rrtype: dnsv1.TypeA},
			}

			// For positive responses, the cryptographic signature is sufficient proof
			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dnsv1.RR{otherRR}, "sub.example.com.")
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should prefer NSEC over NSEC3 when both present", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}
			nsec3 := &dnsv1.NSEC3{
				Hdr:        dnsv1.RR_Header{Name: "abc123.example.com.", Rrtype: dnsv1.TypeNSEC3},
				Hash:       dnsv1.SHA1,
				Salt:       "",
				Iterations: 0,
			}

			// Should use NSEC and succeed
			err := sut.validateWildcardProof("*.example.com.", "sub.example.com.", []dnsv1.RR{nsec, nsec3}, "sub.example.com.")
			Expect(err).Should(Succeed())
		})
	})

	Describe("validateWildcardExpansionDetails", func() {
		It("should fail when RRset has fewer labels than RRSIG claims", func() {
			err := sut.validateWildcardExpansionDetails("example.com.", "example.com.", 3, nil, "sub.example.com.")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("invalid wildcard"))
		})

		It("should construct correct wildcard name", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.example.com.",
			}

			// sub.example.com with RRSIG labels=2 -> wildcard is *.example.com
			err := sut.validateWildcardExpansionDetails("sub.example.com.", "example.com.", 2, []dnsv1.RR{nsec},
				"sub.example.com.")
			Expect(err).Should(Succeed())
		})

		It("should handle multi-level wildcards", func() {
			nsec := &dnsv1.NSEC{
				Hdr:        dnsv1.RR_Header{Name: "a.sub.example.com.", Rrtype: dnsv1.TypeNSEC},
				NextDomain: "zzz.sub.example.com.",
			}

			// test.sub.example.com with RRSIG labels=3 -> wildcard is *.sub.example.com
			err := sut.validateWildcardExpansionDetails("test.sub.example.com.", "example.com.", 3, []dnsv1.RR{nsec},
				"test.sub.example.com.")
			Expect(err).Should(Succeed())
		})
	})
})
