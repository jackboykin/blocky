package config

import (
	"net/netip"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

var _ = Describe("ClientLookupConfig", func() {
	var cfg ClientLookup

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = ClientLookup{
			Upstream:        Upstream{Net: NetProtocolTcpUdp, Host: "host"},
			SingleNameOrder: []uint{1, 2},
			ClientnameIPMapping: map[string][]netip.Addr{
				"client8": {netip.MustParseAddr("1.2.3.5")},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg = ClientLookup{}
			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		When("enabled", func() {
			It("should be true", func() {
				By("upstream", func() {
					cfg := ClientLookup{
						Upstream:            Upstream{Net: NetProtocolTcpUdp, Host: "host"},
						ClientnameIPMapping: nil,
					}

					Expect(cfg.IsEnabled()).Should(BeTrue())
				})

				By("mapping", func() {
					cfg := ClientLookup{
						ClientnameIPMapping: map[string][]netip.Addr{
							"client8": {netip.MustParseAddr("1.2.3.5")},
						},
					}

					Expect(cfg.IsEnabled()).Should(BeTrue())
				})
			})
		})
	})

	Describe("UnmarshalYAML", func() {
		It("unmaps IPv4-mapped client IPs", func() {
			var c ClientLookup
			Expect(yaml.UnmarshalStrict([]byte("clients:\n  laptop: ['::ffff:192.168.1.2']"), &c)).Should(Succeed())
			Expect(c.ClientnameIPMapping).Should(HaveKeyWithValue("laptop", []netip.Addr{netip.MustParseAddr("192.168.1.2")}))
		})

		It("rejects zoned client IPs", func() {
			var c ClientLookup
			Expect(yaml.UnmarshalStrict([]byte("clients:\n  laptop: ['fe80::1%eth0']"), &c)).ShouldNot(Succeed())
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("client IP mapping:")))
		})
	})
})
