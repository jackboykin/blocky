package resolver

import "codeberg.org/miekg/dns/dnsutil"

// searchDomainOrParent returns the entry of m whose key equals domain or is its
// closest parent domain, walking label boundaries with dnsutil.Next. Keys and
// domain must use the same canonical form (case, trailing dot).
func searchDomainOrParent[T any](m map[string]T, domain string) (match string, value T, found bool) {
	if domain == "" || len(m) == 0 {
		return "", value, false
	}

	for offset, end := 0, false; !end; offset, end = dnsutil.Next(domain, offset) {
		match = domain[offset:]
		if value, found = m[match]; found {
			return match, value, true
		}
	}

	return "", value, false
}
