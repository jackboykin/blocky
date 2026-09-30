package util

import (
	"slices"

	"codeberg.org/miekg/dns"
)

// EDNS0Option is an interface for all EDNS0 options as type constraint for generics.
type EDNS0Option interface {
	*dns.SUBNET | *dns.EDE | *dns.NSID | *dns.COOKIE
	dns.EDNS0
}

// HasEdns0 reports whether msg carries an OPT record. The dns package folds the OPT record into
// the message: unpacking one sets UDPSize to at least 512, and anything in the pseudo section or
// an EDNS0 flag makes Pack write one.
func HasEdns0(msg *dns.Msg) bool {
	return msg.UDPSize > 0 || len(msg.Pseudo) > 0 ||
		msg.Security || msg.CompactAnswers || msg.Delegation || msg.Z > 0
}

// SetEdns0 makes msg carry an OPT record advertising udpSize, with the DO bit set to do.
func SetEdns0(msg *dns.Msg, udpSize uint16, do bool) {
	msg.UDPSize, msg.Security = udpSize, do
}

// RemoveEdns0Record removes the OPT record, with all its options, from the given message.
// If the OPT record is removed, true will be returned.
func RemoveEdns0Record(msg *dns.Msg) bool {
	if msg == nil || !HasEdns0(msg) {
		return false
	}

	// the upper bits of an extended rcode live in the OPT record
	msg.Rcode &= 0xF
	msg.UDPSize, msg.Version, msg.Z = 0, 0, 0
	msg.Security, msg.CompactAnswers, msg.Delegation = false, false, false
	msg.Pseudo = nil

	return true
}

// GetEdns0Option returns the option of type T from the OPT record of the given message.
// If the option is not found, nil will be returned.
func GetEdns0Option[T EDNS0Option](msg *dns.Msg) T {
	if msg == nil {
		return nil
	}

	for _, rr := range msg.Pseudo {
		if o, ok := rr.(T); ok {
			return o
		}
	}

	return nil
}

// RemoveEdns0Option removes the option of type T from the OPT record of the given message.
// If there are no more options in the OPT record, the OPT record will be removed.
// If the option is successfully removed, true will be returned.
func RemoveEdns0Option[T EDNS0Option](msg *dns.Msg) bool {
	return removeEdns0Option[T](msg, true)
}

// RemoveEdns0OptionKeepRecord removes the option of type T from the OPT record of the given
// message, keeping the OPT record itself even when it becomes empty: on a request its header
// still carries the DO bit and the UDP buffer size the client advertised, and a response to an
// EDNS0 query must have one (RFC 6891 section 6.1.1).
// If the option is successfully removed, true will be returned.
func RemoveEdns0OptionKeepRecord[T EDNS0Option](msg *dns.Msg) bool {
	return removeEdns0Option[T](msg, false)
}

func removeEdns0Option[T EDNS0Option](msg *dns.Msg, dropEmptyRecord bool) bool {
	if msg == nil {
		return false
	}

	i := slices.IndexFunc(msg.Pseudo, func(rr dns.RR) bool {
		_, ok := rr.(T)

		return ok
	})
	if i < 0 {
		return false
	}

	// a fresh slice: the pseudo section may be shared with a copy of msg
	msg.Pseudo = slices.Concat(msg.Pseudo[:i], msg.Pseudo[i+1:])

	if dropEmptyRecord && len(msg.Pseudo) == 0 {
		RemoveEdns0Record(msg)
	}

	return true
}

// SetEdns0Option adds the given option to the OPT record of the given message.
// If an option of the same type already exists, it will be replaced.
// If the option is successfully set, true will be returned.
func SetEdns0Option(msg *dns.Msg, opt dns.EDNS0) bool {
	if msg == nil || opt == nil {
		return false
	}

	code := dns.RRToCode(opt)

	// a fresh slice: the pseudo section may be shared with a copy of msg
	pseudo := make([]dns.RR, 0, len(msg.Pseudo)+1)

	for _, o := range msg.Pseudo {
		if e, ok := o.(dns.EDNS0); !ok || dns.RRToCode(e) != code {
			pseudo = append(pseudo, o)
		}
	}

	pseudo = append(pseudo, opt)
	msg.Pseudo = pseudo

	return true
}
