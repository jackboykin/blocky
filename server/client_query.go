package server

import (
	"codeberg.org/miekg/dns"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
)

// clientQuery holds the properties of a query as the client itself sent it.
//
// The resolver chain mutates request.Req in place: ECS, DNSSEC and the upstream EDNS0 buffer floor
// may add or enlarge an OPT record the client never sent, and the DNSSEC resolver overwrites the DO
// bit because a validating resolver must always query upstream with DO set (RFC 4035 §3.2.1). The
// properties the response has to be normalized against are therefore captured before resolution
// starts, and applied afterwards by normalizeResponse.
type clientQuery struct {
	// maxResponseSize is the largest response the client accepts, derived from its own EDNS0
	// buffer size rather than the buffer the chain advertised upstream.
	maxResponseSize int

	// hadEdns0 records whether the query carried an OPT record.
	hadEdns0 bool

	// wantsDNSSEC is the state of the EDNS0 DO bit in the query.
	wantsDNSSEC bool

	// wantsAD records whether the client signalled interest in the AD bit, by setting AD in the
	// query (RFC 6840 §5.7) or by setting DO, which counts as the same signal (§5.8).
	wantsAD bool

	// recursionDesired is the state of the RD bit in the query.
	recursionDesired bool

	// qType is the QTYPE of the query, which drives the "explicitly requested" exception when
	// DNSSEC records are stripped. Zero when the query carries no question at all.
	qType uint16
}

// ednsUDPSize is the EDNS0 UDP buffer size blocky advertises to its clients.
const ednsUDPSize = 4096

func newClientQuery(request *model.Request) clientQuery {
	do := request.Req.Security

	// like every other resolver in the chain, only the first question is considered
	var qType uint16
	if len(request.Req.Question) > 0 {
		qType = dns.RRToType(request.Req.Question[0])
	}

	return clientQuery{
		maxResponseSize:  getMaxResponseSize(request),
		hadEdns0:         util.HasEdns0(request.Req),
		wantsDNSSEC:      do,
		wantsAD:          do || request.Req.AuthenticatedData,
		recursionDesired: request.Req.RecursionDesired,
		qType:            qType,
	}
}

// normalizeResponse adapts res to the query the client actually sent. It is the last step before
// the response goes on the wire.
func (q clientQuery) normalizeResponse(res *dns.Msg) {
	res.RecursionAvailable = q.recursionDesired

	if !q.wantsAD {
		// RFC 6840 §5.8: only report authenticated data to a client that asked for it by setting
		// DO or AD. The DNSSEC resolver sets AD on every response it validates, without knowing
		// what the client asked for.
		res.AuthenticatedData = false
	}

	if !q.wantsDNSSEC {
		// RFC 4035 §3.2.1: the DNSSEC records the chain requested upstream on the client's behalf
		// are for us to validate with, not for the client to receive. Stub resolvers may reject a
		// response carrying RRs they never asked for. Runs before Truncate, so stripping them can
		// keep a signed answer under the client's buffer size instead of truncating it.
		util.StripDNSSECRecords(res, q.qType)
	}

	if !q.hadEdns0 {
		// don't return an OPT record to a client that didn't use EDNS0 (RFC 6891 section 7)
		util.RemoveEdns0Record(res)
	} else {
		// Blocky doesn't implement DNS Cookies (RFC 7873), so a Server Cookie in the response is
		// one an upstream issued for blocky itself, and blocky can't validate it when the client
		// returns it. Passing it on also makes the presence of a cookie depend on which upstream
		// answered and on whether the answer came from the cache (stored without an OPT record),
		// and a client that tracks cookie support per server address — c-ares does — discards the
		// cookieless answers of such a flip-flopping server as spoofed.
		util.RemoveEdns0OptionKeepRecord[*dns.COOKIE](res)

		// RFC 3225 §3: the DO bit of the query is copied into the response
		res.Security = q.wantsDNSSEC

		// RFC 6891 §6.1.1: a response to an EDNS0 query must carry an OPT record. Cache hits
		// are served from bytes packed without one; resolvers such as systemd-resolved read
		// its absence as a server without EDNS0 support and downgrade. The dns package only packs
		// an OPT record for a buffer size above 512 (or with a flag or option set), and writes
		// a smaller size as zero, which RFC 6891 §6.2.4 makes a peer read as 512 anyway: so
		// advertise blocky's own buffer size unless the response carries a larger one.
		if res.UDPSize <= dns.MinMsgSize {
			res.UDPSize = ednsUDPSize
		}
	}

	// The dns package compresses every message with records, so this truncates only what doesn't
	// fit compressed.
	util.Truncate(res, q.maxResponseSize)
}

// For TCP returns 64k
// For UDP returns EDNS UDP size or if not present, 512
func getMaxResponseSize(req *model.Request) int {
	if req.Protocol == model.RequestProtocolTCP {
		return dns.MaxMsgSize
	}

	if req.Req.UDPSize > 0 {
		return int(req.Req.UDPSize)
	}

	return dns.MinMsgSize
}
