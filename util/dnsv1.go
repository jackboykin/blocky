package util

// Temporary bridge to github.com/miekg/dns (v1), whose network layer blocky still uses to send
// and receive messages. Delete it once the server and the upstream clients move to
// codeberg.org/miekg/dns.

import (
	"time"

	"codeberg.org/miekg/dns"
	dnsv1 "github.com/miekg/dns"
)

// MsgToV1 converts m through its wire form.
func MsgToV1(m *dns.Msg) (*dnsv1.Msg, error) {
	buf, err := PackMsg(m)
	if err != nil {
		return nil, err
	}

	m1 := new(dnsv1.Msg)
	if err := m1.Unpack(buf); err != nil {
		return nil, err
	}

	return m1, nil
}

// MsgFromV1 converts m1 through its wire form.
func MsgFromV1(m1 *dnsv1.Msg) (*dns.Msg, error) {
	buf, err := m1.Pack()
	if err != nil {
		return nil, err
	}

	return UnpackMsg(buf)
}

// ExchangeV1 sends msg through exchange, a v1 exchange.
func ExchangeV1(
	msg *dns.Msg, exchange func(*dnsv1.Msg) (*dnsv1.Msg, time.Duration, error),
) (*dns.Msg, time.Duration, error) {
	m1, err := MsgToV1(msg)
	if err != nil {
		return nil, 0, err
	}

	r1, rtt, err := exchange(m1)
	if err != nil {
		return nil, rtt, err
	}

	resp, err := MsgFromV1(r1)

	return resp, rtt, err
}
