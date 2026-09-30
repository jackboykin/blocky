package dnssec

import "codeberg.org/miekg/dns/dnsutil"

// splitName returns the labels of name, and none for the root or the empty name.
// dnsutil.Split returns the root as the label "." and the empty name as one empty label.
func splitName(name string) []string {
	if name == "." || name == "" {
		return nil
	}

	return dnsutil.Split(name)
}

// isSubDomain reports whether the fully qualified child is parent or below it.
// dnsutil.IsBelow needs both names fully qualified and indexes out of range otherwise.
// A parent without the trailing dot never matches, as its last label differs from the
// child's.
func isSubDomain(parent, child string) bool {
	return dnsutil.IsFqdn(parent) && dnsutil.IsBelow(parent, child)
}

// canonicalName returns name fully qualified with ASCII letters lowercased (RFC 4034 §6.2),
// leaving every other byte as it is. dnsutil.Canonical maps over runes, which turns bytes
// that aren't valid UTF-8 into U+FFFD, and so different names into the same one.
func canonicalName(name string) string {
	b := []byte(dnsutil.Fqdn(name))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}

	return string(b)
}
