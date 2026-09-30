package resolver

import (
	"context"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
)

// RebindingProtectionResolver drops answers that contain private, loopback, link-local
// or unspecified IPs for non-allowlisted domains (DNS rebinding protection).
//
// It sits above the blocking resolver and the cache in the chain. Only RESOLVED and
// CACHED responses are inspected: answers from conditional upstreams, custom DNS, the
// hosts file, special-use domain handling and blocking are recognized by response
// type and pass through untouched. Sitting above the cache means cached answers —
// including entries synced from redis — are re-inspected on every hit; the cache in
// turn stores only upstream-derived answers (see isCacheableResponseType), so CACHED
// implies upstream origin. Internal lookups (e.g. blocking's FQDN client identifiers)
// enter the chain below this resolver and bypass it entirely.
//
// Known gap: DNS64-synthesized answers (SYNTHESIZED) are upstream-derived but pass
// through uninspected — see the NAT64/DNS64 note in the rebinding documentation.
type RebindingProtectionResolver struct {
	configurable[*config.RebindingProtection]
	NextResolver
	typed

	allowedDomains map[string]struct{}
}

// NewRebindingProtectionResolver returns a new resolver instance
func NewRebindingProtectionResolver(cfg config.RebindingProtection) *RebindingProtectionResolver {
	domains := cfg.NormalizedAllowedDomains()

	allowed := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		allowed[domain] = struct{}{}
	}

	return &RebindingProtectionResolver{
		configurable:   withConfig(&cfg),
		typed:          withType("rebinding_protection"),
		allowedDomains: allowed,
	}
}

// Resolve inspects the next resolver's answer and replaces it with an empty REBIND
// response if it contains a non-public IP.
func (r *RebindingProtectionResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if !r.IsEnabled() {
		return r.next.Resolve(ctx, request)
	}

	response, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	if response == nil || response.Res == nil {
		return response, nil
	}

	// only answers originating from the general upstreams are inspected — directly
	// (RESOLVED) or served from the cache (CACHED, incl. entries synced via redis;
	// the cache stores only upstream-derived answers). Anything else (blocked,
	// conditional, custom DNS, hosts file, SUDN, ...) is trusted local/internal
	// data and passes through untouched — except DNS64-synthesized answers, which
	// are upstream-derived but currently uninspected (documented NAT64/DNS64 gap).
	if response.RType != model.ResponseTypeRESOLVED && response.RType != model.ResponseTypeCACHED {
		return response, nil
	}

	// scan first: most answers are public, so the common path skips question-name
	// extraction and the allowlist walk entirely; the outcome is order-independent
	ip := findBlockedIPInMsg(response.Res)
	if !ip.IsValid() {
		return response, nil
	}

	// the question name decides the allowlist match; without exactly one
	// question the answers cannot be attributed to a single name, so the
	// allowlist never applies (fail closed)
	var domain string
	if len(request.Req.Question) == 1 {
		domain = util.ExtractDomain(request.Req.Question[0])
		if r.isAllowed(domain) {
			return response, nil
		}
	}

	_, logger := r.log(ctx)
	logger.WithField(logFieldDomain, util.Obfuscate(domain)).
		Debugf("dropped answer with non-public IP %s", util.Obfuscate(ip.String()))

	// fixed reason: it becomes a Prometheus label via MetricsResolver, and the IP is
	// attacker-chosen — embedding it would allow unbounded cardinality growth
	return model.NewResponseWithRcode(request, dns.RcodeSuccess, model.ResponseTypeREBIND,
		"REBIND (rebinding protection)"), nil
}

// isAllowed reports whether the queried domain matches an allowlist entry exactly
// or is a subdomain of one.
func (r *RebindingProtectionResolver) isAllowed(domain string) bool {
	_, _, found := searchDomainOrParent(r.allowedDomains, domain)

	return found
}

// findBlockedIPInMsg returns the first non-public IP found in any section of the
// message: upstreams may place address records not only in the answer but also in
// the additional section (e.g. HTTPS/SVCB target addresses, RFC 9460 §5) or the
// authority section, and clients may consume them from there.
func findBlockedIPInMsg(msg *dns.Msg) netip.Addr {
	for _, section := range [][]dns.RR{msg.Answer, msg.Extra, msg.Ns} {
		if ip := findBlockedIP(section); ip.IsValid() {
			return ip
		}
	}

	return netip.Addr{}
}

// findBlockedIP returns the first non-public IP found in the A/AAAA records or HTTPS/SVCB ip hints of the
// given record section, or the zero Addr if there is none.
func findBlockedIP(answers []dns.RR) netip.Addr {
	for _, rr := range answers {
		switch v := rr.(type) {
		case *dns.A:
			if ip := v.Addr.Unmap(); isBlockedIP(ip) {
				return ip
			}
		case *dns.AAAA:
			if ip := v.Addr.Unmap(); isBlockedIP(ip) {
				return ip
			}
		case *dns.HTTPS:
			if ip := findBlockedHintIP(v.Value); ip.IsValid() {
				return ip
			}
		case *dns.SVCB:
			if ip := findBlockedHintIP(v.Value); ip.IsValid() {
				return ip
			}
		}
	}

	return netip.Addr{}
}

// findBlockedHintIP returns the first non-public IP in the ipv4hint/ipv6hint
// SvcParams of an HTTPS/SVCB record, or the zero Addr if there is none.
func findBlockedHintIP(values []svcb.Pair) netip.Addr {
	var hints []netip.Addr

	for _, kv := range values {
		switch hint := kv.(type) {
		case *svcb.IPV4HINT:
			hints = hint.Hint
		case *svcb.IPV6HINT:
			hints = hint.Hint
		default:
			continue
		}

		for _, raw := range hints {
			if ip := raw.Unmap(); isBlockedIP(ip) {
				return ip
			}
		}
	}

	return netip.Addr{}
}

// isBlockedIP reports whether ip belongs to one of the fixed non-public ranges:
// RFC1918/ULA, loopback, link-local or unspecified. IPv4-mapped IPv6 addresses must
// be unmapped first. The zero Addr (address-less record)
// returns false by design.
func isBlockedIP(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
