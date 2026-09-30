package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/0xERR0R/blocky/util"
)

// dnsTimeout bounds each dial, write and read of an exchange, as github.com/miekg/dns v1 did.
const dnsTimeout = 2 * time.Second

var errDNSIDMismatch = errors.New("dns: response ID doesn't match the query")

// dnsTransport exchanges DNS messages over UDP, TCP or TLS (DoT).
//
// It doesn't use dns.Client: that packs into the query's Data and reads the reply into the same
// buffer, and a query may be shared by concurrent exchanges (parallel_best). It also fails a UDP
// exchange on the first reply with another ID, which an off-path sender can provoke; such
// replies are skipped here.
type dnsTransport struct {
	Net       string // "udp", "tcp" or "tcp-tls"
	TLSConfig *tls.Config
}

// dial connects to addr.
func (t *dnsTransport) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dnsTimeout}

	if t.Net == transportTCPTLS {
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: t.TLSConfig}

		return tlsDialer.DialContext(ctx, transportTCP, addr)
	}

	return dialer.DialContext(ctx, t.Net, addr)
}

// exchange sends msg to addr over a new connection and returns the reply.
func (t *dnsTransport) exchange(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	conn, err := t.dial(ctx, addr)
	if err != nil {
		return nil, 0, err
	}

	defer conn.Close()

	return exchangeWithConn(ctx, msg, conn)
}

// exchangeWithConn sends msg over conn and returns the reply. Every read and write is bounded by
// dnsTimeout and the deadline of ctx, and cancelling ctx interrupts them.
func exchangeWithConn(ctx context.Context, msg *dns.Msg, conn net.Conn) (*dns.Msg, time.Duration, error) {
	query, err := util.PackMsg(msg)
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()

	deadline := start.Add(dnsTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, err
	}

	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(interrupted)
	})

	// Once the exchange is over, the interruption must be too: a pooled conn is reused, and the
	// next exchange sets a deadline of its own.
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()

	_, isUDP := conn.(net.PacketConn)

	if err := writeMsg(conn, query, isUDP); err != nil {
		return nil, time.Since(start), err
	}

	for {
		resp, err := readMsg(conn, isUDP, max(int(msg.UDPSize), dns.MinMsgSize))
		if err != nil {
			return nil, time.Since(start), err
		}

		if resp.ID == msg.ID {
			return resp, time.Since(start), nil
		}

		// On UDP a reply with another ID may be a late one to an earlier query, or forged.
		if !isUDP {
			return nil, time.Since(start), errDNSIDMismatch
		}
	}
}

func writeMsg(conn net.Conn, msg []byte, isUDP bool) error {
	if !isUDP {
		if len(msg) > dns.MaxMsgSize {
			return fmt.Errorf("dns: message of %d bytes is too large", len(msg))
		}

		//nolint:gosec // bounded by the check above
		msg = append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(msg)), uint16(len(msg))), msg...)
	}

	_, err := conn.Write(msg)

	return err
}

// readMsg reads a message from conn. On UDP, a message larger than udpSize arrives truncated and
// fails to unpack.
func readMsg(conn net.Conn, isUDP bool, udpSize int) (*dns.Msg, error) {
	if isUDP {
		buf := make([]byte, udpSize)

		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}

		return util.UnpackMsg(buf[:n])
	}

	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}

	buf := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	return util.UnpackMsg(buf)
}
