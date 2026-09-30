package resolver

import (
	"github.com/0xERR0R/blocky/util"
	dnsv1 "github.com/miekg/dns"
)

// Helpers shared by the mock upstream servers (UDP/TCP, DoT, DoQ) to build
// answer functions and finalize replies, so the identical logic isn't copied
// per protocol.

// rrAnswerFn returns a mock answer function that replies with the given resource
// records (in dns.NewRR text form).
func rrAnswerFn(answers ...string) func(request *dnsv1.Msg) *dnsv1.Msg {
	return func(_ *dnsv1.Msg) *dnsv1.Msg {
		msg := new(dnsv1.Msg)

		for _, a := range answers {
			rr, err := dnsv1.NewRR(a)
			util.FatalOnError("can't create RR", err)

			msg.Answer = append(msg.Answer, rr)
		}

		return msg
	}
}

// errorAnswerFn returns a mock answer function that replies with the given Rcode.
func errorAnswerFn(errorCode int) func(request *dnsv1.Msg) *dnsv1.Msg {
	return func(_ *dnsv1.Msg) *dnsv1.Msg {
		msg := new(dnsv1.Msg)
		msg.Rcode = errorCode

		return msg
	}
}

// mockReply turns the response produced by a mock answer function into a reply to
// request. dns.Msg.SetReply resets Rcode to success, so a non-success Rcode set
// by the answer function is restored afterwards.
func mockReply(request, response *dnsv1.Msg) *dnsv1.Msg {
	rCode := response.Rcode
	response.SetReply(request)

	if rCode != 0 {
		response.Rcode = rCode
	}

	return response
}
