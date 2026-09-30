package dnssec

// This file checks an RRSIG's signature over an RRset, around dns.RRSIG.Verify:
//
//   - Verify doesn't check that the records form an RRset the RRSIG covers (type, class,
//     owner, label count, signer above the owner), so checkCoverage does.
//   - Verify doesn't lowercase the signer name (RFC 4034 §6.2).
//   - Verify orders the RRset by dns.Compare rather than canonical rdata (RFC 4034 §6.3),
//     which differs for CAA and multi-string TXT, and keeps duplicate RRs. Either breaks
//     valid signatures, so the rdata goes in canonical and deduplicated as RFC 3597
//     records, which Compare orders by their wire bytes.
//   - Verify rewrites the RRset and RRSIG in place, and they may be answered to the
//     client, so it only ever sees copies.
//
// Verify and DNSKEY.ToDS lowercase owner names with dnsutil.Canonical, which turns bytes
// that aren't valid UTF-8 into U+FFFD, so a signature over such a name fails. That's a
// false Bogus, which fails closed.

import (
	"errors"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

var errRRset = errors.New("dns: bad rrset")

// verifySignature reports whether sig is a valid signature by key over rrset. It doesn't
// check the validity period.
func verifySignature(sig *dns.RRSIG, key *dns.DNSKEY, rrset []dns.RR) error {
	if err := checkCoverage(sig, key, rrset); err != nil {
		return err
	}

	set, err := canonicalRRset(rrset)
	if err != nil {
		return err
	}

	sigCopy := *sig // the rdata holds no references, so this is a deep copy
	sigCopy.SignerName = canonicalName(sig.SignerName)

	return sigCopy.Verify(key, set, &dns.SignOption{})
}

// checkCoverage checks that rrset is an RRset that sig covers and key can have signed.
func checkCoverage(sig *dns.RRSIG, key *dns.DNSKEY, rrset []dns.RR) error {
	if !isRRset(rrset) {
		return errRRset
	}

	signer := canonicalName(sig.SignerName)
	if sig.KeyTag != key.KeyTag() || sig.Hdr.Class != key.Hdr.Class || sig.Algorithm != key.Algorithm ||
		!equalName(signer, key.Hdr.Name) || key.Protocol != dnskeyProtocolValue || key.Flags&dns.FlagZONE == 0 {
		return dns.ErrKey
	}

	owner := rrset[0].Header()
	if owner.Class != sig.Hdr.Class ||
		dns.RRToType(rrset[0]) != sig.TypeCovered ||
		uint8(dnsutil.Labels(owner.Name)) < sig.Labels || //nolint:gosec // a name has at most 127 labels
		!equalName(owner.Name, sig.Hdr.Name) ||
		!strings.HasSuffix(canonicalName(owner.Name), signer) {
		return errRRset
	}

	return nil
}

func isRRset(rrset []dns.RR) bool {
	if len(rrset) == 0 {
		return false
	}

	first := rrset[0].Header()
	firstType := dns.RRToType(rrset[0])

	for _, rr := range rrset[1:] {
		h := rr.Header()
		if h.Name != first.Name || h.Class != first.Class || dns.RRToType(rr) != firstType {
			return false
		}
	}

	return true
}

// equalName reports whether a and b are the same name, ignoring ASCII case.
func equalName(a, b string) bool {
	return len(a) == len(b) && canonicalName(a) == canonicalName(b)
}

// canonicalRRset returns copies of rrset's records as RFC 3597 records holding their
// canonical wire rdata (RFC 4034 §6.2), sorted, without duplicates.
func canonicalRRset(rrset []dns.RR) ([]dns.RR, error) {
	set := make([]*dns.RFC3597, 0, len(rrset))

	for _, rr := range rrset {
		c := rr.Clone()
		lowercaseRdataNames(c)

		// ToRFC3597 packs with name compression. Each type's rdata holds at most one
		// compressible name, so with a root owner there's nothing to point it at.
		owner := c.Header().Name
		c.Header().Name = "."

		u := new(dns.RFC3597)
		if err := u.ToRFC3597(c); err != nil {
			return nil, err
		}

		u.Hdr.Name = owner
		set = append(set, u)
	}

	byRdata := func(a, b *dns.RFC3597) int { return strings.Compare(a.RFC3597.Data, b.RFC3597.Data) }
	slices.SortFunc(set, byRdata)
	set = slices.CompactFunc(set, func(a, b *dns.RFC3597) bool { return byRdata(a, b) == 0 })

	out := make([]dns.RR, len(set))
	for i, u := range set {
		out[i] = u
	}

	return out, nil
}

// lowercaseRdataNames lowercases the domain names in rr's rdata, for the types RFC 4034
// §6.2 (as amended by RFC 6840 §5.1) lists.
//
//nolint:funlen // one case per type listed
func lowercaseRdataNames(rr dns.RR) {
	c := canonicalName

	switch x := rr.(type) {
	case *dns.NS:
		x.Ns = c(x.Ns)
	case *dns.MD:
		x.Md = c(x.Md)
	case *dns.MF:
		x.Mf = c(x.Mf)
	case *dns.CNAME:
		x.Target = c(x.Target)
	case *dns.SOA:
		x.Ns, x.Mbox = c(x.Ns), c(x.Mbox)
	case *dns.MB:
		x.Mb = c(x.Mb)
	case *dns.MG:
		x.Mg = c(x.Mg)
	case *dns.MR:
		x.Mr = c(x.Mr)
	case *dns.PTR:
		x.Ptr = c(x.Ptr)
	case *dns.MINFO:
		x.Rmail, x.Email = c(x.Rmail), c(x.Email)
	case *dns.MX:
		x.Mx = c(x.Mx)
	case *dns.RP:
		x.Mbox, x.Txt = c(x.Mbox), c(x.Txt)
	case *dns.AFSDB:
		x.Hostname = c(x.Hostname)
	case *dns.RT:
		x.Host = c(x.Host)
	case *dns.SIG:
		x.SignerName = c(x.SignerName)
	case *dns.PX:
		x.Map822, x.Mapx400 = c(x.Map822), c(x.Mapx400)
	case *dns.NAPTR:
		x.Replacement = c(x.Replacement)
	case *dns.KX:
		x.Exchanger = c(x.Exchanger)
	case *dns.SRV:
		x.Target = c(x.Target)
	case *dns.DNAME:
		x.Target = c(x.Target)
	}
}
