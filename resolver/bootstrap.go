package resolver

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/hashicorp/go-multierror"
	dnsv1 "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var errArbitrarySystemResolverRequest = errors.New(
	"cannot resolve arbitrary requests using the system resolver",
)

type bootstrapConfig struct {
	config.BootstrapDNS

	connectIPVersion config.IPVersion
	timeout          config.Duration
}

func newBootstrapConfig(cfg *config.Config) *bootstrapConfig {
	return &bootstrapConfig{
		BootstrapDNS: cfg.BootstrapDNS,

		connectIPVersion: cfg.ConnectIPVersion,
		timeout:          cfg.Upstreams.Timeout,
	}
}

// Bootstrap allows resolving hostnames using the configured bootstrap DNS.
type Bootstrap struct {
	configurable[*bootstrapConfig]
	typed

	resolver    Resolver
	bootstraped bootstrapedResolvers

	// To allow replacing during tests
	systemResolver *net.Resolver
	dialer         interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
}

// NewBootstrap creates and returns a new Bootstrap.
// Internally, it uses a CachingResolver and an UpstreamResolver.
func NewBootstrap(ctx context.Context, cfg *config.Config) (b *Bootstrap, err error) {
	// Create b in multiple steps: Bootstrap and UpstreamResolver have a cyclic dependency
	// This also prevents the GC to clean up these two structs, but is not currently an
	// issue since they stay allocated until the process terminates
	b = &Bootstrap{
		configurable: withConfig(newBootstrapConfig(cfg)),
		typed:        withType("bootstrap"),

		systemResolver: net.DefaultResolver,
		dialer:         new(net.Dialer),
	}

	ctx, logger := b.log(ctx)

	bootstraped, err := newBootstrapedResolvers(b, cfg.BootstrapDNS, cfg.Upstreams, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap resolvers: %w", err)
	}

	if len(bootstraped) == 0 {
		logger.Info("bootstrapDns is not configured, will use system resolver")

		return b, nil
	}

	pbCfg := config.NewUpstreamGroup("<bootstrap>", cfg.Upstreams, nil)
	pbCfg.Groups = nil // To be on the safe side it doesn't try to use anything besides the bootstrap

	// Always enable prefetching to avoid stalling user requests
	// Otherwise, a request to blocky could end up waiting for 2 DNS requests:
	//   1. lookup the DNS server IP
	//   2. forward the user request to the server looked-up in 1
	cachingCfg := cfg.Caching
	cachingCfg.EnablePrefetch()

	if !cachingCfg.MinCachingTime.IsAboveZero() {
		// Set a min time in case the user didn't to avoid prefetching too often
		cachingCfg.MinCachingTime = config.Duration(time.Hour)
	}

	b.bootstraped = bootstraped
	cachingResolver, _ := newCachingResolver(ctx, cachingCfg, config.DNSSEC{}, nil, false)

	b.resolver = Chain(
		NewFilteringResolver(cfg.Filtering),
		// false: no metrics, to not overwrite the main blocking resolver ones
		cachingResolver,
		newParallelBestResolver(pbCfg, bootstraped.Resolvers()),
	)

	return b, nil
}

func (b *Bootstrap) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if b.resolver == nil {
		// We could implement most queries using the `b.systemResolver.Lookup*` functions,
		// but that requires a lot of boilerplate to translate from `dns` to `net` and back.
		return nil, errArbitrarySystemResolverRequest
	}

	// Add bootstrap prefix to all inner resolver logs
	ctx, _ = b.log(ctx)

	resp, err := b.resolver.Resolve(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("bootstrap DNS resolution failed: %w", err)
	}

	return resp, nil
}

func (b *Bootstrap) UpstreamIPs(ctx context.Context, r *UpstreamResolver) (*IPSet, error) {
	hostname := r.Upstream().Host

	if ip := util.ParseIP(hostname); ip.IsValid() { // nil-safe when hostname is an IP: makes writing tests easier
		return newIPSet([]netip.Addr{ip}), nil
	}

	// Use IPs from DNS stamp if available (avoids bootstrap resolution)
	if ips := r.Upstream().IPs; len(ips) > 0 {
		return newIPSet(ips), nil
	}

	ips, err := b.resolveUpstream(ctx, r, hostname)
	if err != nil {
		return nil, fmt.Errorf("could not resolve IPs for upstream %s: %w", hostname, err)
	}

	return newIPSet(ips), nil
}

func (b *Bootstrap) resolveUpstream(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	if ips, ok := b.bootstraped[r]; ok {
		// Special path for bootstraped upstreams to avoid infinite recursion
		return ips, nil
	}

	ctx, cancel := context.WithTimeout(ctx, b.cfg.timeout.ToDuration())
	defer cancel()

	// Use system resolver if no bootstrap is configured
	if b.resolver == nil {
		ips, err := b.systemResolver.LookupNetIP(ctx, b.cfg.connectIPVersion.Net(), host)
		if err != nil {
			return nil, fmt.Errorf("system resolver lookup failed for '%s': %w", host, err)
		}

		// LookupNetIP can return IPv4 addresses in their IPv4-mapped IPv6 form.
		for i, ip := range ips {
			ips[i] = ip.Unmap()
		}

		return ips, nil
	}

	return b.resolve(ctx, host, b.cfg.connectIPVersion.QTypes())
}

// NewHTTPTransport returns a new http.Transport that uses b to resolve hostnames
func (b *Bootstrap) NewHTTPTransport() *http.Transport {
	transport := util.DefaultHTTPTransport()
	transport.DialContext = b.dialContext

	return transport
}

func (b *Bootstrap) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if b.resolver == nil {
		conn, err := b.dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("system dialer failed to connect to '%s': %w", addr, err)
		}

		return conn, nil
	}

	ctx, logger := b.logWithFields(ctx, logrus.Fields{"network": network, "addr": addr})

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		logger.Errorf("dial error: %s", err)

		return nil, fmt.Errorf("failed to parse dial address '%s': %w", addr, err)
	}

	var qTypes []dnsv1.Type

	switch {
	case b.cfg.connectIPVersion != config.IPVersionDual: // ignore `network` if a specific version is configured
		qTypes = b.cfg.connectIPVersion.QTypes()
	case strings.HasSuffix(network, "4"):
		qTypes = config.IPVersionV4.QTypes()
	case strings.HasSuffix(network, "6"):
		qTypes = config.IPVersionV6.QTypes()
	default:
		qTypes = config.IPVersionDual.QTypes()
	}

	// Resolve the host with the bootstrap DNS
	ips, err := b.resolve(ctx, host, qTypes)
	if err != nil {
		logger.Errorf("resolve error: %s", err)

		return nil, fmt.Errorf("failed to resolve host '%s' via bootstrap DNS: %w", host, err)
	}

	// Shuffle so that load is spread across the resolved addresses. On a dial
	// failure we fall back to the remaining addresses (e.g. the other IP
	// family) instead of consuming the whole attempt — the standard dialer
	// does this dual-stack fallback for us, but we bypass it by resolving the
	// host ourselves and dialing a single address.
	rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })

	var dialErr *multierror.Error

	for _, ip := range ips {
		logger.WithField("ip", ip).Tracef("dialing %s", host)

		// Use the standard dialer to actually connect
		addrWithIP := net.JoinHostPort(ip.String(), port)

		conn, err := b.dialer.DialContext(ctx, network, addrWithIP)
		if err == nil {
			return conn, nil
		}

		dialErr = multierror.Append(dialErr, fmt.Errorf("dial '%s': %w", addrWithIP, err))
	}

	return nil, fmt.Errorf("failed to dial '%s' (resolved from '%s'): %w", addr, host, dialErr.ErrorOrNil())
}

func (b *Bootstrap) resolve(ctx context.Context, hostname string, qTypes []dnsv1.Type) (ips []netip.Addr, err error) {
	ips = make([]netip.Addr, 0, len(qTypes))

	for _, qType := range qTypes {
		qIPs, qErr := b.resolveType(ctx, hostname, qType)
		if qErr != nil {
			err = multierror.Append(err, qErr)

			continue
		}

		ips = append(ips, qIPs...)
	}

	if err == nil && len(ips) == 0 {
		return nil, fmt.Errorf("no such host %s", hostname)
	}

	if err != nil {
		return ips, fmt.Errorf("failed to resolve %s: %w", hostname, err)
	}

	return ips, nil
}

func (b *Bootstrap) resolveType(ctx context.Context, hostname string, qType dnsv1.Type) (ips []netip.Addr, err error) {
	if ip := util.ParseIP(hostname); ip.IsValid() {
		return []netip.Addr{ip}, nil
	}

	ctx, _ = b.log(ctx)

	req := model.Request{
		Req: util.NewMsgWithQuestion(hostname, qType),
	}

	rsp, err := b.resolver.Resolve(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed for %s (type %s): %w", hostname, qType, err)
	}

	if rsp.Res.Rcode != dnsv1.RcodeSuccess {
		return nil, nil
	}

	ips = make([]netip.Addr, 0, len(rsp.Res.Answer))

	for _, a := range rsp.Res.Answer {
		switch rr := a.(type) {
		case *dnsv1.A:
			ips = append(ips, util.AddrFromIP(rr.A))
		case *dnsv1.AAAA:
			ips = append(ips, util.AddrFromIP(rr.AAAA))
		}
	}

	return ips, nil
}

// map of bootstraped resolvers to their hardcoded IPs
type bootstrapedResolvers map[Resolver][]netip.Addr

func newBootstrapedResolvers(
	b *Bootstrap, cfg config.BootstrapDNS, upstreamsCfg config.Upstreams, logger *logrus.Entry,
) (bootstrapedResolvers, error) {
	upstreamIPs := make(bootstrapedResolvers, len(cfg))

	var multiErr *multierror.Error

	for i, upstreamCfg := range cfg {
		i := i + 1 // user visible index should start at 1

		if upstreamCfg.ResolvFile != "" {
			if err := b.addResolvFileUpstreams(upstreamIPs, upstreamCfg, upstreamsCfg, logger); err != nil {
				multiErr = multierror.Append(multiErr, fmt.Errorf("item %d: %w", i, err))
			}

			continue
		}

		upstream := upstreamCfg.Upstream

		if upstream.IsDefault() {
			multiErr = multierror.Append(
				multiErr,
				fmt.Errorf("item %d: upstream not configured (ips=%v)", i, upstreamCfg.IPs),
			)

			continue
		}

		ips := make([]netip.Addr, 0, len(upstreamCfg.IPs)+1)

		if ip := util.ParseIP(upstream.Host); ip.IsValid() {
			ips = append(ips, ip)
		} else if upstream.Net == config.NetProtocolTcpUdp {
			multiErr = multierror.Append(
				multiErr,
				fmt.Errorf("item %d: '%s': protocol %s must use IP instead of hostname", i, upstream, upstream.Net),
			)

			continue
		}

		ips = append(ips, upstreamCfg.IPs...)

		if len(ips) == 0 {
			multiErr = multierror.Append(multiErr, fmt.Errorf("item %d: '%s': no IPs configured", i, upstream))

			continue
		}

		resolver := newUpstreamResolverUnchecked(newUpstreamConfig(upstream, upstreamsCfg), b)

		upstreamIPs[resolver] = ips
	}

	if multiErr != nil {
		return nil, fmt.Errorf("invalid bootstrapDns configuration: %w", multiErr)
	}

	return upstreamIPs, nil
}

// defaultDNSPort is the fallback bootstrap port. resolv.conf(5) carries no
// per-nameserver port, so dns.ClientConfigFromFile always reports "53"; we
// still parse cc.Port defensively in case that ever changes.
const defaultDNSPort uint16 = 53

// addResolvFileUpstreams reads nameservers from a resolv.conf(5) file and adds
// one plain-DNS bootstrap upstream per nameserver to upstreamIPs. This lets
// systems whose DHCP-provided resolvers live outside /etc/resolv.conf (e.g.
// OpenWrt's /tmp/resolv.conf.auto) point blocky at the right file.
func (b *Bootstrap) addResolvFileUpstreams(
	upstreamIPs bootstrapedResolvers, upstreamCfg config.BootstrappedUpstream,
	upstreamsCfg config.Upstreams, logger *logrus.Entry,
) error {
	if !upstreamCfg.Upstream.IsDefault() || len(upstreamCfg.IPs) > 0 {
		return errors.New("resolvFile cannot be combined with upstream/ips in the same entry")
	}

	path := upstreamCfg.ResolvFile

	cc, err := dnsv1.ClientConfigFromFile(path)
	if err != nil {
		return fmt.Errorf("resolvFile '%s': %w", path, err)
	}

	port := defaultDNSPort
	if p, err := strconv.ParseUint(cc.Port, 10, 16); err == nil {
		port = uint16(p)
	}

	var added int

	for _, server := range cc.Servers {
		ip := util.ParseIP(server)
		if !ip.IsValid() {
			continue
		}

		upstream := config.Upstream{Net: config.NetProtocolTcpUdp, Host: server, Port: port}
		resolver := newUpstreamResolverUnchecked(newUpstreamConfig(upstream, upstreamsCfg), b)
		upstreamIPs[resolver] = []netip.Addr{ip}
		added++
	}

	if added == 0 {
		return fmt.Errorf("resolvFile '%s': no usable nameservers", path)
	}

	logger.Infof("loaded %d bootstrap nameserver(s) from resolvFile '%s'", added, path)

	return nil
}

func (br bootstrapedResolvers) Resolvers() []Resolver {
	return slices.Collect(maps.Keys(br))
}

type IPSet struct {
	values []netip.Addr
	index  uint32
}

func newIPSet(ips []netip.Addr) *IPSet {
	return &IPSet{values: ips}
}

func (ips *IPSet) Current() netip.Addr {
	idx := atomic.LoadUint32(&ips.index)

	return ips.values[idx]
}

func (ips *IPSet) Next() {
	oldIP := ips.index
	newIP := uint32(int(ips.index+1) % len(ips.values)) //nolint:gosec // index and len are small practical values

	// We don't care about the result: if the call fails,
	// it means the value was incremented by another goroutine
	_ = atomic.CompareAndSwapUint32(&ips.index, oldIP, newIP)
}
