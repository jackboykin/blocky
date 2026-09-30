package server

// Temporary bridge to the github.com/miekg/dns (v1) server. Delete it once the server moves to
// codeberg.org/miekg/dns.

import (
	"context"

	"codeberg.org/miekg/dns"
	"github.com/0xERR0R/blocky/util"
	dnsv1 "github.com/miekg/dns"
)

// v1Handler adapts handle to the v1 server. A request handle can't be given is answered with
// FORMERR.
func v1Handler(
	ctx context.Context, handle func(context.Context, dnsv1.ResponseWriter, *dns.Msg),
) func(dnsv1.ResponseWriter, *dnsv1.Msg) {
	return func(w dnsv1.ResponseWriter, m1 *dnsv1.Msg) {
		m, err := util.MsgFromV1(m1)
		if err != nil {
			util.LogOnError(ctx, "can't write message: ", w.WriteMsg(new(dnsv1.Msg).SetRcodeFormatError(m1)))

			return
		}

		handle(ctx, w, m)
	}
}

// v1Writer writes messages to a v1 ResponseWriter the way they pack, so the size they were
// truncated to holds.
type v1Writer struct {
	dnsv1.ResponseWriter
}

func (w v1Writer) WriteMsg(m *dns.Msg) error {
	buf, err := util.PackMsg(m)
	if err != nil {
		return err
	}

	_, err = w.Write(buf)

	return err
}
