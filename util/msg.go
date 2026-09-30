package util

import (
	"slices"
	"sort"

	"codeberg.org/miekg/dns"
)

// CloneMsg is a deep copy: m.Copy() shares records and sections.
func CloneMsg(m *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHeader: m.MsgHeader,
		Question:  cloneRRs(m.Question),
		Answer:    cloneRRs(m.Answer),
		Ns:        cloneRRs(m.Ns),
		Extra:     cloneRRs(m.Extra),
		Pseudo:    cloneRRs(m.Pseudo),
	}
}

func cloneRRs(rrs []dns.RR) []dns.RR {
	if rrs == nil {
		return nil
	}

	clones := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		clones[i] = rr.Clone()
	}

	return clones
}

// PackMsg leaves m alone: m.Pack() packs into m.Data, which may be shared.
func PackMsg(m *dns.Msg) ([]byte, error) {
	c := m.Copy()
	c.Data = nil
	c.Pseudo = packablePseudo(c.Pseudo)

	if err := c.Pack(); err != nil {
		return nil, err
	}

	return c.Data, nil
}

// packablePseudo swaps an ECS option of family 0 /0, which the dns package can't pack, for
// family 1 /0, which means the same (RFC 7871 section 7.1.2).
func packablePseudo(pseudo []dns.RR) []dns.RR {
	for i, rr := range pseudo {
		if so, ok := rr.(*dns.SUBNET); ok && so.Family == 0 && so.Netmask == 0 {
			v4 := *so
			v4.Family = 1

			pseudo = slices.Clone(pseudo)
			pseudo[i] = &v4

			return pseudo
		}
	}

	return pseudo
}

// UnpackMsg returns a message that doesn't hold buf, which may be shared.
func UnpackMsg(buf []byte) (*dns.Msg, error) {
	m := &dns.Msg{Data: buf}
	if err := m.Unpack(); err != nil {
		return nil, err
	}

	m.Data = nil

	return m, nil
}

// Truncate keeps the longest run of records that fits and sets TC; dnsutil.Truncate drops all.
func Truncate(m *dns.Msg, size int) {
	size = max(size, dns.MinMsgSize)

	if m.Len() <= size {
		return
	}

	answer, ns, extra := m.Answer, m.Ns, m.Extra
	nAnswer, nNs := len(answer), len(ns)

	keep := func(n int) {
		m.Answer = answer[:min(n, nAnswer)]
		m.Ns = ns[:min(max(n-nAnswer, 0), nNs)]
		m.Extra = extra[:min(max(n-nAnswer-nNs, 0), len(extra))]
	}

	total := nAnswer + nNs + len(extra)
	n := sort.Search(total+1, func(n int) bool {
		keep(n)
		buf, err := PackMsg(m)

		return err != nil || len(buf) > size
	})

	if n > total {
		keep(total)

		return
	}

	keep(max(n-1, 0))
	m.Truncated = true
}
