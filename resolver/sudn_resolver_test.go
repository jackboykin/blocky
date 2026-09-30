package resolver

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	dnsv1 "github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("SudnResolver", Label("sudnResolver"), func() {
	var (
		sut       *SpecialUseDomainNamesResolver
		sutConfig config.SUDN
		m         *mockResolver

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		var err error

		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sutConfig, err = config.WithDefaults[config.SUDN]()
		Expect(err).Should(Succeed())
	})

	JustBeforeEach(func() {
		mockAnswer, err := util.NewMsgWithAnswer("example.com.", 300, A, "123.145.123.145")
		Expect(err).Should(Succeed())

		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)

		sut = NewSpecialUseDomainNamesResolver(sutConfig)
		sut.Next(m)
	})

	Describe("handlers", func() {
		It("should have correct response type", func() {
			for domain, handler := range sudnHandlers {
				resp, err := sut.Resolve(ctx, newRequest(domain, A))
				Expect(err).Should(Succeed())

				if handler == nil {
					Expect(resp).ShouldNot(HaveResponseType(ResponseTypeSPECIAL))

					continue
				}

				Expect(resp).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeSPECIAL),
							HaveReason("Special-Use Domain Name"),
						))
			}
		})
	})

	Describe("Resolve", func() {
		//nolint:unparam // linter thinks `qName` is always `A` because of "RFC 6762 Appendix G" table
		entry := func(qType dnsv1.Type, qName string, expectedRCode int, extraMatchers ...any) TableEntry {
			GinkgoHelper()

			var verb string
			switch expectedRCode {
			case dnsv1.RcodeSuccess:
				verb = "resolve"
			case dnsv1.RcodeNameError:
				verb = "block"
			}

			description := fmt.Sprintf("should %s %s IN %s", verb, qName, qType)

			args := make([]any, 0, 3+len(extraMatchers))
			args = append(args, qType, qName, expectedRCode)
			args = append(args, extraMatchers...)

			return Entry(description, args...)
		}

		It("should be true by default", func() {
			Expect(sutConfig.IsEnabled()).Should(BeTrue())
		})

		When("enabled", func() {
			It("should be true", func() {
				sutConfig.Enable = true
				Expect(sutConfig.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				sutConfig.Enable = false
				Expect(sutConfig.IsEnabled()).Should(BeFalse())
			})
		})

		DescribeTable("handled domains",
			func(qType dnsv1.Type, qName string, expectedRCode int, extraMatchers ...types.GomegaMatcher) {
				resp, err := sut.Resolve(ctx, newRequest(qName, qType))
				Expect(err).Should(Succeed())
				Expect(resp).Should(SatisfyAll(
					HaveResponseType(ResponseTypeSPECIAL),
					HaveReason("Special-Use Domain Name"),
					HaveReturnCode(expectedRCode),
				))

				switch expectedRCode {
				case dnsv1.RcodeSuccess:
					Expect(resp).Should(HaveTTL(BeNumerically("==", 0)))
				case dnsv1.RcodeNameError:
					Expect(resp).Should(HaveNoAnswer())
				}

				Expect(resp).Should(SatisfyAll(extraMatchers...))
			},

			entry(A, "1.0.0.10.in-addr.arpa.", dnsv1.RcodeNameError),
			entry(A, "something.test.", dnsv1.RcodeNameError),
			entry(A, "something.localhost.", dnsv1.RcodeSuccess, BeDNSRecord("something.localhost.", A, loopbackV4.String())),
			entry(AAAA, "thing.localhost.", dnsv1.RcodeSuccess, BeDNSRecord("thing.localhost.", AAAA, loopbackV6.String())),
			entry(HTTPS, "something.localhost.", dnsv1.RcodeNameError),
			entry(A, "something.invalid.", dnsv1.RcodeNameError),
			entry(A, "something.local.", dnsv1.RcodeNameError),
			entry(HTTPS, "something.local.", dnsv1.RcodeNameError),
			entry(A, "1.0.254.169.in-addr.arpa.", dnsv1.RcodeNameError),
			entry(A, "something.intranet.", dnsv1.RcodeNameError),
			entry(A, "something.internal.", dnsv1.RcodeNameError),
			entry(A, "something.private.", dnsv1.RcodeNameError),
			entry(A, "something.corp.", dnsv1.RcodeNameError),
			entry(A, "something.home.", dnsv1.RcodeNameError),
			entry(A, "something.lan.", dnsv1.RcodeNameError),
			entry(A, "something.onion.", dnsv1.RcodeNameError),

			// DNS names are case-insensitive (RFC 4343): mixed-case queries
			// (clients, dns0x20 randomization) must not skip special-use handling
			entry(A, "LOCALHOST.", dnsv1.RcodeSuccess, BeDNSRecord("LOCALHOST.", A, loopbackV4.String())),
			entry(A, "SoMeThInG.TeSt.", dnsv1.RcodeNameError),
		)

		When("RFC 6762 Appendix G is disabled", func() {
			BeforeEach(func() {
				sutConfig.RFC6762AppendixG = false
			})

			DescribeTable("",
				func(qType dnsv1.Type, qName string, expectedRCode int) {
					resp, err := sut.Resolve(ctx, newRequest(qName, qType))
					Expect(err).Should(Succeed())
					Expect(resp).Should(HaveReturnCode(expectedRCode))
					Expect(resp).ShouldNot(HaveResponseType(ResponseTypeSPECIAL))
				},

				entry(A, "something.intranet.", dnsv1.RcodeSuccess),
				entry(A, "something.intranet.", dnsv1.RcodeSuccess),
				entry(A, "something.internal.", dnsv1.RcodeSuccess),
				entry(A, "something.private.", dnsv1.RcodeSuccess),
				entry(A, "something.corp.", dnsv1.RcodeSuccess),
				entry(A, "something.home.", dnsv1.RcodeSuccess),
				entry(A, "something.lan.", dnsv1.RcodeSuccess),
			)
		})

		It("should forward example.com", func() {
			Expect(sut.Resolve(ctx, newRequest("example.com", A))).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "123.145.123.145"),
						HaveTTL(BeNumerically("==", 300)),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dnsv1.RcodeSuccess),
					))
		})

		It("should forward home.arpa. IN DS", func() {
			Expect(sut.Resolve(ctx, newRequest("something.home.arpa.", DS))).
				Should(
					SatisfyAll(
						// setup code doesn't care about the question
						BeDNSRecord("example.com.", A, "123.145.123.145"),
						HaveTTL(BeNumerically("==", 300)),
						HaveResponseType(ResponseTypeRESOLVED),
						HaveReturnCode(dnsv1.RcodeSuccess),
					))
		})

		It("should forward non special use domains", func() {
			resp, err := sut.Resolve(ctx, newRequest("something.not-special.", AAAA))
			Expect(err).Should(Succeed())
			Expect(resp).ShouldNot(HaveResponseType(ResponseTypeSPECIAL))
		})

		// RFC 9462: Discovery of Designated Resolvers (DDR).
		// Section 4 + 6.1 + 6.4: blocky has no Designated Resolvers to announce
		// and MUST NOT forward queries for `resolver.arpa.` upstream. Reply
		// NODATA (NOERROR + empty Answer) for every QTYPE across the zone.
		DescribeTable("RFC 9462 resolver.arpa zone (NODATA)",
			func(qType dnsv1.Type, qName string) {
				resp, err := sut.Resolve(ctx, newRequest(qName, qType))
				Expect(err).Should(Succeed())
				Expect(resp).Should(SatisfyAll(
					HaveResponseType(ResponseTypeSPECIAL),
					HaveReason("Special-Use Domain Name"),
					HaveReturnCode(dnsv1.RcodeSuccess),
					HaveNoAnswer(),
				))
			},
			Entry("SVCB for _dns.resolver.arpa.", dnsv1.Type(dnsv1.TypeSVCB), "_dns.resolver.arpa."),
			Entry("A for _dns.resolver.arpa.", A, "_dns.resolver.arpa."),
			Entry("AAAA for _dns.resolver.arpa.", AAAA, "_dns.resolver.arpa."),
			Entry("A for the zone apex resolver.arpa.", A, "resolver.arpa."),
			Entry("HTTPS for an arbitrary subdomain", HTTPS, "foo.bar.resolver.arpa."),
			Entry("DS for the zone apex (no forwarding)", DS, "resolver.arpa."),
		)
	})
})
