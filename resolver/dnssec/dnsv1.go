package dnssec

// Temporary bridge to github.com/miekg/dns (v1). The validator works on
// codeberg.org/miekg/dns (v2) internally, but its callers still hand it v1 messages and
// its sub-queries go out through model.Request/model.Response, which carry *dnsv1.Msg.
// Delete this file once model.Request moves to v2.

import (
	"bytes"
	"errors"
	"slices"

	"codeberg.org/miekg/dns"
	dnsv1 "github.com/miekg/dns"
)

var errLossyConversion = errors.New("message changes in conversion to codeberg.org/miekg/dns")

// responseToV2 converts the response under validation, with question as its question
// section, so the question's name is represented the same way as the records' names.
func responseToV2(response *dnsv1.Msg, question dnsv1.Question) (*dns.Msg, error) {
	withQuestion := *response
	withQuestion.Question = []dnsv1.Question{question}

	return msgToV2(&withQuestion)
}

// msgToV2 converts m through its wire form. v2 can't hold every message v1 can: it reads
// a label holding a dot as two labels, and rejects some rdata v1 packs. So the result
// must pack back to the same question and records, or m is refused.
func msgToV2(m *dnsv1.Msg) (*dns.Msg, error) {
	// Packing sets the extended rcode in the OPT RR, which may be shared with the
	// client's response, so it packs a copy.
	own := *m
	own.Extra = slices.Clone(m.Extra)

	for i, rr := range own.Extra {
		if opt, ok := rr.(*dnsv1.OPT); ok {
			own.Extra[i] = dnsv1.Copy(opt)
		}
	}

	buf, err := own.Pack()
	if err != nil {
		return nil, err
	}

	m2 := &dns.Msg{Data: buf}
	if err := m2.Unpack(); err != nil {
		return nil, err
	}

	back, err := msgToV1(m2)
	if err != nil {
		return nil, err
	}

	if !sameQuestions(m.Question, back.Question) ||
		!sameRRs(m.Answer, back.Answer) || !sameRRs(m.Ns, back.Ns) || !sameRRs(withoutOPT(m.Extra), withoutOPT(back.Extra)) {
		return nil, errLossyConversion
	}

	return m2, nil
}

func msgToV1(m *dns.Msg) (*dnsv1.Msg, error) {
	if err := m.Pack(); err != nil {
		return nil, err
	}

	m1 := new(dnsv1.Msg)
	if err := m1.Unpack(m.Data); err != nil {
		return nil, err
	}

	return m1, nil
}

func sameQuestions(a, b []dnsv1.Question) bool {
	return slices.EqualFunc(a, b, func(x, y dnsv1.Question) bool {
		wx, wy := nameWire(x.Name), nameWire(y.Name)

		return x.Qtype == y.Qtype && x.Qclass == y.Qclass && wx != nil && bytes.Equal(wx, wy)
	})
}

func sameRRs(a, b []dnsv1.RR) bool {
	return slices.EqualFunc(a, b, func(x, y dnsv1.RR) bool {
		wx, wy := rrWire(x), rrWire(y)

		return wx != nil && bytes.Equal(wx, wy)
	})
}

func withoutOPT(rrs []dnsv1.RR) []dnsv1.RR {
	return slices.DeleteFunc(slices.Clone(rrs), func(rr dnsv1.RR) bool {
		_, isOPT := rr.(*dnsv1.OPT)

		return isOPT
	})
}

func rrWire(rr dnsv1.RR) []byte {
	buf := make([]byte, dnsv1.Len(rr)+1)

	off, err := dnsv1.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil
	}

	return buf[:off]
}

func nameWire(name string) []byte {
	const maxNameOctets = 255

	buf := make([]byte, maxNameOctets)

	off, err := dnsv1.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		return nil
	}

	return buf[:off]
}
