package e2e

import (
	"context"
	"net/netip"

	"codeberg.org/miekg/dns"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// addECSOption adds a full-prefix EDNS0 CLIENT-SUBNET option (the only form the ECS e2e
// tests need) to the given DNS message.
func addECSOption(msg *dns.Msg, ip netip.Addr) {
	e := &dns.SUBNET{Address: ip, Netmask: uint8(ip.BitLen())} // full prefix
	if ip.Is4() {
		e.Family = 1 // IPv4
	} else {
		e.Family = 2 // IPv6
	}

	msg.Pseudo = append(msg.Pseudo, e)
}

var _ = Describe("EDNS Client Subnet (ECS)", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("ECS as client identifier", func() {
		When("useAsClient is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ecs:
					  useAsClient: true
					  ipv4Mask: 32
					`))
				Expect(err).Should(Succeed())
			})

			It("should resolve queries when ECS option is present", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, netip.MustParseAddr("10.0.0.1"))

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})

	Describe("ECS forwarding", func() {
		When("forward is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ecs:
					  forward: true
					  ipv4Mask: 24
					`))
				Expect(err).Should(Succeed())
			})

			It("should resolve queries with ECS forwarding enabled", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, netip.MustParseAddr("10.1.2.3"))

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})

	Describe("ECS IPv4/IPv6 masks", func() {
		When("custom masks are configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					ecs:
					  useAsClient: true
					  ipv4Mask: 24
					  ipv6Mask: 48
					`))
				Expect(err).Should(Succeed())
			})

			It("should resolve queries with custom ECS masks configured", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, netip.MustParseAddr("10.1.2.3"))

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})
})
