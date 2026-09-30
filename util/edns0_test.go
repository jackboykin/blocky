package util

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	exampleDomain = "example.com"
	testTxt       = "test"
)

var _ = Describe("EDNS0 utils", func() {
	var baseMsg *dns.Msg

	BeforeEach(func() {
		baseMsg = new(dns.Msg)
		baseMsg.Extra = append(baseMsg.Extra, &dns.TXT{
			Hdr: dns.Header{Name: exampleDomain + "."},
			Txt: []string{testTxt},
		})
	})

	Describe("HasEdns0", func() {
		It("is false for a message without an OPT record", func() {
			Expect(HasEdns0(baseMsg)).Should(BeFalse())
		})

		It("is true for an unpacked OPT record advertising 512 or less", func() {
			// the dns package reads such a record as UDPSize 512
			baseMsg.UDPSize = dns.MinMsgSize

			Expect(HasEdns0(baseMsg)).Should(BeTrue())
		})

		It("is true for an option without a UDP size", func() {
			baseMsg.Pseudo = []dns.RR{new(dns.EDE)}

			Expect(HasEdns0(baseMsg)).Should(BeTrue())
		})

		It("is true for the DO bit alone", func() {
			baseMsg.Security = true

			Expect(HasEdns0(baseMsg)).Should(BeTrue())
		})
	})

	Describe("SetEdns0", func() {
		It("sets the UDP size and DO bit, keeping the options", func() {
			baseMsg.Pseudo = []dns.RR{new(dns.COOKIE)}

			SetEdns0(baseMsg, 1232, true)

			Expect(baseMsg.UDPSize).Should(BeNumerically("==", 1232))
			Expect(baseMsg.Security).Should(BeTrue())
			Expect(baseMsg).Should(HaveEdnsOption(dns.CodeCOOKIE))
		})
	})

	Describe("RemoveEdns0Record", func() {
		When("OPT record is present", func() {
			BeforeEach(func() {
				SetEdns0(baseMsg, 1232, true)
				baseMsg.Pseudo = []dns.RR{new(dns.COOKIE)}
			})

			It("should remove it", func() {
				Expect(RemoveEdns0Record(baseMsg)).Should(BeTrue())

				Expect(HasEdns0(baseMsg)).Should(BeFalse())
				Expect(baseMsg.Extra).Should(HaveLen(1), "the other records are kept")
			})

			It("keeps no extended rcode, which would pack an OPT record again", func() {
				baseMsg.Rcode = dns.RcodeBadVers

				RemoveEdns0Record(baseMsg)

				Expect(baseMsg.Rcode).Should(BeNumerically("<=", 0xF))
				buf, err := PackMsg(baseMsg)
				Expect(err).Should(Succeed())
				packed, err := UnpackMsg(buf)
				Expect(err).Should(Succeed())
				Expect(HasEdns0(packed)).Should(BeFalse())
			})
		})

		When("OPT record is not present", func() {
			It("should do nothing ", func() {
				Expect(RemoveEdns0Record(baseMsg)).Should(BeFalse())
			})
		})

		When("message is nil", func() {
			It("should do nothing", func() {
				Expect(RemoveEdns0Record(nil)).Should(BeFalse())
			})
		})
	})

	Describe("GetEdns0Option", func() {
		When("Option is present", func() {
			var eso *dns.SUBNET

			BeforeEach(func() {
				eso = &dns.SUBNET{Address: netip.MustParseAddr("192.168.0.0"), Family: 1, Netmask: 24}
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.EDE), eso)
			})

			It("should return it", func() {
				Expect(GetEdns0Option[*dns.SUBNET](baseMsg)).Should(BeIdenticalTo(eso))
			})
		})

		When("Option is not present", func() {
			BeforeEach(func() {
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.EDE))
			})

			It("should return nil", func() {
				Expect(GetEdns0Option[*dns.SUBNET](baseMsg)).Should(BeNil())
			})
		})

		When("OPT record is not present", func() {
			It("should return nil", func() {
				Expect(GetEdns0Option[*dns.SUBNET](baseMsg)).Should(BeNil())
			})
		})

		When("message is nil", func() {
			It("should return nil", func() {
				Expect(GetEdns0Option[*dns.SUBNET](nil)).Should(BeNil())
			})
		})
	})

	Describe("RemoveEdns0Option", func() {
		When("Option is present", func() {
			BeforeEach(func() {
				SetEdns0(baseMsg, 1232, true)
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.SUBNET))
			})

			It("should remove it", func() {
				Expect(RemoveEdns0Option[*dns.SUBNET](baseMsg)).Should(BeTrue())

				Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.CodeSUBNET))
			})

			It("should remove the OPT record once it holds no option", func() {
				Expect(RemoveEdns0Option[*dns.SUBNET](baseMsg)).Should(BeTrue())

				Expect(HasEdns0(baseMsg)).Should(BeFalse())
			})
		})

		When("Option is not present", func() {
			BeforeEach(func() {
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.EDE))
			})
			It("should return false", func() {
				Expect(RemoveEdns0Option[*dns.SUBNET](baseMsg)).Should(BeFalse())
			})
		})

		When("OPT record is not present", func() {
			It("should return false", func() {
				Expect(RemoveEdns0Option[*dns.SUBNET](baseMsg)).Should(BeFalse())
			})
		})

		When("message is nil", func() {
			It("should return false", func() {
				Expect(RemoveEdns0Option[*dns.SUBNET](nil)).Should(BeFalse())
			})
		})
	})

	Describe("RemoveEdns0OptionKeepRecord", func() {
		When("the removed option is the only one in the OPT record", func() {
			BeforeEach(func() {
				SetEdns0(baseMsg, 1232, true)
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.COOKIE))
			})

			It("should keep the OPT record with its UDP size and DO bit", func() {
				Expect(RemoveEdns0OptionKeepRecord[*dns.COOKIE](baseMsg)).Should(BeTrue())

				Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.CodeCOOKIE))

				Expect(HasEdns0(baseMsg)).Should(BeTrue())
				Expect(baseMsg.UDPSize).Should(BeNumerically("==", 1232))
				Expect(baseMsg.Security).Should(BeTrue())
			})
		})

		When("other options are present", func() {
			BeforeEach(func() {
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.COOKIE), new(dns.SUBNET))
			})

			It("should remove only the given option", func() {
				Expect(RemoveEdns0OptionKeepRecord[*dns.COOKIE](baseMsg)).Should(BeTrue())

				Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.CodeCOOKIE))
				Expect(baseMsg).Should(HaveEdnsOption(dns.CodeSUBNET))
			})
		})

		When("Option is not present", func() {
			BeforeEach(func() {
				baseMsg.Pseudo = append(baseMsg.Pseudo, new(dns.EDE))
			})

			It("should return false and keep the OPT record", func() {
				Expect(RemoveEdns0OptionKeepRecord[*dns.COOKIE](baseMsg)).Should(BeFalse())

				Expect(HasEdns0(baseMsg)).Should(BeTrue())
			})
		})

		When("OPT record is not present", func() {
			It("should return false", func() {
				Expect(RemoveEdns0OptionKeepRecord[*dns.COOKIE](baseMsg)).Should(BeFalse())
			})
		})

		When("message is nil", func() {
			It("should return false", func() {
				Expect(RemoveEdns0OptionKeepRecord[*dns.COOKIE](nil)).Should(BeFalse())
			})
		})
	})

	Describe("SetEdns0Option", func() {
		When("Option is not present", func() {
			BeforeEach(func() {
				Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.CodeSUBNET))
				Expect(SetEdns0Option(baseMsg, new(dns.EDE))).Should(BeTrue())
			})

			It("should add the option", func() {
				Expect(SetEdns0Option(baseMsg, new(dns.SUBNET))).Should(BeTrue())

				Expect(baseMsg).Should(HaveEdnsOption(dns.CodeSUBNET))
				Expect(baseMsg).Should(HaveEdnsOption(dns.CodeEDE))
			})
		})

		When("Option is present", func() {
			var (
				eso  *dns.SUBNET
				eso2 *dns.SUBNET
			)

			BeforeEach(func() {
				eso = &dns.SUBNET{Address: netip.MustParseAddr("1.1.1.1"), Family: 1, Netmask: 32}
				eso2 = &dns.SUBNET{Address: netip.MustParseAddr("2.2.2.2"), Family: 1, Netmask: 32}

				Expect(SetEdns0Option(baseMsg, eso)).Should(BeTrue())
			})

			It("should replace it", func() {
				Expect(GetEdns0Option[*dns.SUBNET](baseMsg)).Should(BeIdenticalTo(eso))
				Expect(SetEdns0Option(baseMsg, eso2)).Should(BeTrue())
				Expect(GetEdns0Option[*dns.SUBNET](baseMsg)).Should(BeIdenticalTo(eso2))
				Expect(baseMsg.Pseudo).Should(HaveLen(1))
			})
		})

		When("message is nil", func() {
			It("should return false", func() {
				Expect(SetEdns0Option(nil, new(dns.SUBNET))).Should(BeFalse())
			})
		})

		When("option is nil", func() {
			It("should do nothing if option is nil", func() {
				Expect(SetEdns0Option(baseMsg, nil)).Should(BeFalse())
			})
		})
	})

	// Msg.Copy shares the pseudo section, so an option helper editing it in place would change
	// the message it was copied from too.
	Describe("on a copy sharing the pseudo section", func() {
		var original, copied *dns.Msg

		BeforeEach(func() {
			original = new(dns.Msg)
			// spare capacity, so an append in place would land in the shared array
			original.Pseudo = make([]dns.RR, 0, 4)
			original.Pseudo = append(original.Pseudo, new(dns.COOKIE), new(dns.SUBNET))
			copied = original.Copy()
		})

		It("SetEdns0Option leaves the original alone", func() {
			SetEdns0Option(copied, new(dns.EDE))

			Expect(original.Pseudo).Should(HaveLen(2))
			Expect(original).ShouldNot(HaveEdnsOption(dns.CodeEDE))
			Expect(original).Should(HaveEdnsOption(dns.CodeCOOKIE))
		})

		It("RemoveEdns0OptionKeepRecord leaves the original alone", func() {
			RemoveEdns0OptionKeepRecord[*dns.COOKIE](copied)

			Expect(original.Pseudo[0]).Should(BeAssignableToTypeOf(new(dns.COOKIE)))
			Expect(original.Pseudo[1]).Should(BeAssignableToTypeOf(new(dns.SUBNET)))
		})
	})
})
