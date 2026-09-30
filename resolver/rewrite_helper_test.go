package resolver

import (
	"net"

	"github.com/0xERR0R/blocky/log"

	dnsv1 "github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RewriteHelper", func() {
	var (
		logger     *logrus.Entry
		rewriteMap map[string]string
	)

	BeforeEach(func() {
		logger = logrus.NewEntry(log.Log())
	})

	BeforeEach(func() {
		rewriteMap = map[string]string{
			"original":  "rewritten",
			"test.zone": "example.com",
		}
	})

	Describe("rewriteDomain", func() {
		When("domain matches rewrite rule exactly", func() {
			It("should not rewrite (exact matches without subdomain are not supported)", func() {
				// The rewriteDomain function only rewrites if domain has suffix ".original"
				// An exact match "original" without the dot prefix is not rewritten
				result, key := rewriteDomain("original", rewriteMap)
				Expect(result).Should(Equal("original"))
				Expect(key).Should(Equal(""))
			})
		})

		When("domain is a subdomain of rewrite rule", func() {
			It("should rewrite the subdomain", func() {
				result, key := rewriteDomain("sub.original", rewriteMap)
				Expect(result).Should(Equal("sub.rewritten"))
				Expect(key).Should(Equal("original"))
			})

			It("should handle multiple levels of subdomains", func() {
				result, key := rewriteDomain("deep.sub.test.zone", rewriteMap)
				Expect(result).Should(Equal("deep.sub.example.com"))
				Expect(key).Should(Equal("test.zone"))
			})
		})

		When("domain does not match any rewrite rule", func() {
			It("should return domain unchanged", func() {
				result, key := rewriteDomain("untouched.domain", rewriteMap)
				Expect(result).Should(Equal("untouched.domain"))
				Expect(key).Should(Equal(""))
			})
		})

		When("domain is parent of rewrite rule", func() {
			It("should not rewrite (pattern must be subdomain match)", func() {
				result, key := rewriteDomain("riginal", rewriteMap)
				Expect(result).Should(Equal("riginal"))
				Expect(key).Should(Equal(""))
			})
		})

		When("rewrite map is empty", func() {
			It("should return domain unchanged", func() {
				result, key := rewriteDomain("any.domain", map[string]string{})
				Expect(result).Should(Equal("any.domain"))
				Expect(key).Should(Equal(""))
			})
		})

		When("domain has mixed case", func() {
			It("should handle case-insensitive matching", func() {
				result, key := rewriteDomain("SUB.ORIGINAL", rewriteMap)
				Expect(result).Should(Equal("sub.rewritten"))
				Expect(key).Should(Equal("original"))
			})
		})
	})

	Describe("rewriteRequest", func() {
		When("request has rewritable domain", func() {
			It("should return rewritten request and track original names", func() {
				req := new(dnsv1.Msg)
				req.SetQuestion(dnsv1.Fqdn("test.original"), dnsv1.TypeA)

				rewritten, originalNames := rewriteRequest(logger, req, rewriteMap)

				Expect(rewritten).ShouldNot(BeNil())
				Expect(rewritten.Question[0].Name).Should(Equal("test.rewritten."))
				Expect(originalNames).Should(HaveKey("test.rewritten."))
				Expect(originalNames["test.rewritten."]).Should(Equal("test.original."))
			})

			It("should not modify original request", func() {
				req := new(dnsv1.Msg)
				req.SetQuestion(dnsv1.Fqdn("test.original"), dnsv1.TypeA)
				originalQuestion := req.Question[0].Name

				rewritten, _ := rewriteRequest(logger, req, rewriteMap)

				Expect(rewritten).ShouldNot(BeNil())
				Expect(req.Question[0].Name).Should(Equal(originalQuestion))
			})
		})

		When("request has multiple questions with rewrites", func() {
			It("should rewrite all applicable questions", func() {
				req := new(dnsv1.Msg)
				req.Question = []dnsv1.Question{
					{Name: dnsv1.Fqdn("sub1.original"), Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
					{Name: dnsv1.Fqdn("sub2.test.zone"), Qtype: dnsv1.TypeAAAA, Qclass: dnsv1.ClassINET},
				}

				rewritten, originalNames := rewriteRequest(logger, req, rewriteMap)

				Expect(rewritten).ShouldNot(BeNil())
				Expect(rewritten.Question[0].Name).Should(Equal("sub1.rewritten."))
				Expect(rewritten.Question[1].Name).Should(Equal("sub2.example.com."))
				Expect(originalNames).Should(HaveLen(2))
			})
		})

		When("request does not match any rewrite rule", func() {
			It("should return nil", func() {
				req := new(dnsv1.Msg)
				req.SetQuestion(dnsv1.Fqdn("untouched.domain"), dnsv1.TypeA)

				rewritten, originalNames := rewriteRequest(logger, req, rewriteMap)

				Expect(rewritten).Should(BeNil())
				Expect(originalNames).Should(BeEmpty())
			})
		})

		When("rewrite map is empty", func() {
			It("should return nil", func() {
				req := new(dnsv1.Msg)
				req.SetQuestion(dnsv1.Fqdn("any.domain"), dnsv1.TypeA)

				rewritten, originalNames := rewriteRequest(logger, req, map[string]string{})

				Expect(rewritten).Should(BeNil())
				Expect(originalNames).Should(BeNil())
			})
		})

		When("request has no questions", func() {
			It("should handle gracefully", func() {
				req := new(dnsv1.Msg)
				req.Question = []dnsv1.Question{}

				rewritten, originalNames := rewriteRequest(logger, req, rewriteMap)

				Expect(rewritten).Should(BeNil())
				Expect(originalNames).Should(BeEmpty())
			})
		})
	})

	Describe("revertRewritesInResponse", func() {
		When("response has rewritten names", func() {
			It("should revert question names", func() {
				resp := new(dnsv1.Msg)
				resp.Question = []dnsv1.Question{
					{Name: "test.rewritten.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
				}

				originalNames := map[string]string{
					"test.rewritten.": "test.original.",
				}

				revertRewritesInResponse(resp, originalNames)

				Expect(resp.Question[0].Name).Should(Equal("test.original."))
			})

			It("should revert answer names", func() {
				resp := new(dnsv1.Msg)
				resp.Answer = []dnsv1.RR{
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "test.rewritten.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
				}

				originalNames := map[string]string{
					"test.rewritten.": "test.original.",
				}

				revertRewritesInResponse(resp, originalNames)

				Expect(resp.Answer[0].Header().Name).Should(Equal("test.original."))
			})

			It("should revert both question and answer names", func() {
				resp := new(dnsv1.Msg)
				resp.Question = []dnsv1.Question{
					{Name: "test.rewritten.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
				}
				resp.Answer = []dnsv1.RR{
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "test.rewritten.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
				}

				originalNames := map[string]string{
					"test.rewritten.": "test.original.",
				}

				revertRewritesInResponse(resp, originalNames)

				Expect(resp.Question[0].Name).Should(Equal("test.original."))
				Expect(resp.Answer[0].Header().Name).Should(Equal("test.original."))
			})

			It("should handle multiple answers", func() {
				resp := new(dnsv1.Msg)
				resp.Answer = []dnsv1.RR{
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "sub1.rewritten.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "sub2.example.com.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
				}

				originalNames := map[string]string{
					"sub1.rewritten.":   "sub1.original.",
					"sub2.example.com.": "sub2.test.zone.",
				}

				revertRewritesInResponse(resp, originalNames)

				Expect(resp.Answer[0].Header().Name).Should(Equal("sub1.original."))
				Expect(resp.Answer[1].Header().Name).Should(Equal("sub2.test.zone."))
			})

			It("should not revert names not in originalNames map", func() {
				resp := new(dnsv1.Msg)
				resp.Question = []dnsv1.Question{
					{Name: "untouched.domain.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
				}
				resp.Answer = []dnsv1.RR{
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "untouched.domain.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
				}

				originalNames := map[string]string{
					"test.rewritten.": "test.original.",
				}

				revertRewritesInResponse(resp, originalNames)

				Expect(resp.Question[0].Name).Should(Equal("untouched.domain."))
				Expect(resp.Answer[0].Header().Name).Should(Equal("untouched.domain."))
			})
		})

		When("originalNames map is empty", func() {
			It("should not modify response", func() {
				resp := new(dnsv1.Msg)
				resp.Question = []dnsv1.Question{
					{Name: "test.domain.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
				}
				resp.Answer = []dnsv1.RR{
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "test.domain.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
				}

				originalQuestion := resp.Question[0].Name
				originalAnswer := resp.Answer[0].Header().Name

				revertRewritesInResponse(resp, map[string]string{})

				Expect(resp.Question[0].Name).Should(Equal(originalQuestion))
				Expect(resp.Answer[0].Header().Name).Should(Equal(originalAnswer))
			})
		})

		When("response has more answers than questions", func() {
			It("should handle all answers", func() {
				resp := new(dnsv1.Msg)
				resp.Question = []dnsv1.Question{
					{Name: "test.rewritten.", Qtype: dnsv1.TypeA, Qclass: dnsv1.ClassINET},
				}
				resp.Answer = []dnsv1.RR{
					&dnsv1.CNAME{
						Hdr:    dnsv1.RR_Header{Name: "test.rewritten.", Rrtype: dnsv1.TypeCNAME, Class: dnsv1.ClassINET, Ttl: 300},
						Target: "target.example.com.",
					},
					&dnsv1.A{
						Hdr: dnsv1.RR_Header{Name: "target.example.com.", Rrtype: dnsv1.TypeA, Class: dnsv1.ClassINET, Ttl: 300},
						A:   nil,
					},
				}

				originalNames := map[string]string{
					"test.rewritten.": "test.original.",
				}

				revertRewritesInResponse(resp, originalNames)

				Expect(resp.Question[0].Name).Should(Equal("test.original."))
				Expect(resp.Answer[0].Header().Name).Should(Equal("test.original."))
				Expect(resp.Answer[1].Header().Name).Should(Equal("target.example.com."))
			})
		})

		When("response has no questions or answers", func() {
			It("should handle gracefully", func() {
				resp := new(dnsv1.Msg)

				originalNames := map[string]string{
					"test.rewritten.": "test.original.",
				}

				// Should not panic
				revertRewritesInResponse(resp, originalNames)
			})
		})
	})

	Describe("Integration: rewrite and revert round-trip", func() {
		It("should preserve original request after rewrite and revert", func() {
			// Create original request
			originalReq := new(dnsv1.Msg)
			originalReq.SetQuestion(dnsv1.Fqdn("sub.original"), dnsv1.TypeA)
			originalQuestion := originalReq.Question[0].Name

			// Rewrite request
			rewritten, originalNames := rewriteRequest(logger, originalReq, rewriteMap)
			Expect(rewritten).ShouldNot(BeNil())
			Expect(rewritten.Question[0].Name).Should(Equal("sub.rewritten."))

			// Simulate response with rewritten name
			resp := new(dnsv1.Msg)
			resp.SetReply(rewritten)
			resp.Answer = []dnsv1.RR{
				&dnsv1.A{
					Hdr: dnsv1.RR_Header{
						Name:   "sub.rewritten.",
						Rrtype: dnsv1.TypeA,
						Class:  dnsv1.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("1.2.3.4"),
				},
			}

			// Revert response
			revertRewritesInResponse(resp, originalNames)

			// Verify original name is restored
			Expect(resp.Question[0].Name).Should(Equal(originalQuestion))
			Expect(resp.Answer[0].Header().Name).Should(Equal(originalQuestion))
		})
	})
})
