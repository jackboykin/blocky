package model

import dnsv1 "github.com/miekg/dns"

// NewResponseWithReason creates a response with a DNS message that has SetReply called.
// This is used when you want to create a response that replies to the request,
// optionally with answer records.
func NewResponseWithReason(request *Request, rtype ResponseType, reason string) *Response {
	response := new(dnsv1.Msg)
	response.SetReply(request.Req)

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewResponseWithAnswers creates a response with a DNS message that has SetReply called
// and the provided answer records added.
func NewResponseWithAnswers(request *Request, answers []dnsv1.RR, rtype ResponseType, reason string) *Response {
	response := new(dnsv1.Msg)
	response.SetReply(request.Req)
	response.Answer = answers

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

// NewResponseWithRcode creates a response with a specific return code using SetRcode.
// This is typically used for empty responses with specific error codes.
func NewResponseWithRcode(request *Request, rcode int, rtype ResponseType, reason string) *Response {
	response := new(dnsv1.Msg)
	response.SetRcode(request.Req, rcode)

	return &Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}
