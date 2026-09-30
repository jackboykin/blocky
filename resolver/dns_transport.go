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

const dnsTimeout = 2 * time.Second

var errDNSIDMismatch = errors.New("dns: response ID doesn't match the query")

// dnsTransport stands in for dns.Client, which packs into the query's buffer (shared by
// parallel_best) and fails a UDP exchange on the first reply with another ID.
type dnsTransport struct {
	Net       string
	TLSConfig *tls.Config
}

func (t *dnsTransport) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dnsTimeout}

	if t.Net == transportTCPTLS {
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: t.TLSConfig}

		return tlsDialer.DialContext(ctx, transportTCP, addr)
	}

	return dialer.DialContext(ctx, t.Net, addr)
}

func (t *dnsTransport) exchange(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	conn, err := t.dial(ctx, addr)
	if err != nil {
		return nil, 0, err
	}

	defer conn.Close()

	return exchangeWithConn(ctx, msg, conn)
}

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

	// a pooled conn outlives the exchange, so the interruption must not
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
