package util

import (
	"sort"

	"codeberg.org/miekg/dns"
)

// CloneMsg returns a deep copy of m, which unlike m.Copy() shares no records or sections with it.
// The copy has no wire data: it is made to be changed, and the dns package sends a message's
// wire data, when it has any, instead of packing its current contents.
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

// PackMsg returns m packed into a new buffer. Unlike m.Pack(), it leaves m as it is, as it may be
// shared: m.Pack() packs into m.Data, reusing its buffer.
func PackMsg(m *dns.Msg) ([]byte, error) {
	c := m.Copy()
	c.Data = nil

	if err := c.Pack(); err != nil {
		return nil, err
	}

	return c.Data, nil
}

// UnpackMsg returns the message packed in buf. Unlike Msg.Unpack, the message doesn't keep buf,
// which may be shared: packing it would write into buf, and sending it would send buf as it is.
func UnpackMsg(buf []byte) (*dns.Msg, error) {
	m := &dns.Msg{Data: buf}
	if err := m.Unpack(); err != nil {
		return nil, err
	}

	m.Data = nil

	return m, nil
}

// Truncate makes m fit into size octets once packed, the way github.com/miekg/dns v1 did:
// it keeps the longest run of records, in section order, that fits, and sets TC if any record
// was dropped. dnsutil.Truncate instead drops every record. A size below 512 counts as 512
// (RFC 6891 section 6.2.5).
func Truncate(m *dns.Msg, size int) {
	size = max(size, dns.MinMsgSize)

	// the uncompressed length, which compression can only shorten
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

	// Each record kept can only grow the packed message, so binary search finds the longest run
	// that fits.
	total := nAnswer + nNs + len(extra)
	n := sort.Search(total+1, func(n int) bool {
		keep(n)
		buf, err := PackMsg(m)

		return err != nil || len(buf) > size
	})

	if n > total {
		keep(total) // it fits compressed

		return
	}

	keep(max(n-1, 0))
	m.Truncated = true
}
