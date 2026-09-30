package model

import "codeberg.org/miekg/dns"

// NewResponseWithReason creates a response with a DNS message that has SetReply called.
// This is used when you want to create a response that replies to the request,
// optionally with answer records.
func NewResponseWithReason(request *Request, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	SetReply(response, request.Req)

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewResponseWithAnswers creates a response with a DNS message that has SetReply called
// and the provided answer records added.
func NewResponseWithAnswers(request *Request, answers []dns.RR, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	SetReply(response, request.Req)
	response.Answer = answers

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewResponseWithRcode creates a response with a specific return code using SetRcode.
// This is typically used for empty responses with specific error codes.
func NewResponseWithRcode(request *Request, rcode uint16, rtype ResponseType, reason string) *Response {
	response := new(dns.Msg)
	SetRcode(response, request.Req, rcode)

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// SetReply makes m a reply to req, the way github.com/miekg/dns v1 did: it takes over req's ID,
// opcode, RD and CD bits, and a copy of its first question, sets rcode to NOERROR, and leaves
// everything else alone. dnsutil.SetReply also empties m's sections, takes over the DO bit and
// shares req's question section.
func SetReply(m, req *dns.Msg) *dns.Msg {
	m.ID = req.ID
	m.Response = true
	m.Opcode = req.Opcode

	if m.Opcode == dns.OpcodeQuery {
		m.RecursionDesired = req.RecursionDesired
		m.CheckingDisabled = req.CheckingDisabled
	}

	m.Rcode = dns.RcodeSuccess

	if len(req.Question) > 0 {
		m.Question = []dns.RR{req.Question[0].Clone()}
	}

	return m
}

// SetRcode makes m a reply to req, see SetReply, with the given rcode.
func SetRcode(m, req *dns.Msg, rcode uint16) *dns.Msg {
	SetReply(m, req)
	m.Rcode = rcode

	return m
}
