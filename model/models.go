package model

//go:generate go tool go-enum -f=$GOFILE --marshal --names
import (
	"net/netip"
	"time"

	dnsv1 "github.com/miekg/dns"
)

// ResponseType represents the type of the response ENUM(
// RESOLVED // the response was resolved by the external upstream resolver
// CACHED // the response was resolved from cache
// BLOCKED // the query was blocked
// CONDITIONAL // the query was resolved by the conditional upstream resolver
// CUSTOMDNS // the query was resolved by a custom rule
// HOSTSFILE // the query was resolved by looking up the hosts file
// FILTERED // the query was filtered by query type
// NOTFQDN // the query was filtered as it is not fqdn conform
// SPECIAL // the query was resolved by the special use domain name resolver
// SYNTHESIZED // the response was synthesized by DNS64
// REBIND // the answer was blocked by the DNS rebinding protection
// BOGUS // the answer failed DNSSEC validation
// )
type ResponseType int

func (t ResponseType) ToExtendedErrorCode() uint16 {
	switch t {
	case ResponseTypeRESOLVED:
		return dnsv1.ExtendedErrorCodeOther
	case ResponseTypeCACHED:
		return dnsv1.ExtendedErrorCodeCachedError
	case ResponseTypeCONDITIONAL:
		return dnsv1.ExtendedErrorCodeForgedAnswer
	case ResponseTypeCUSTOMDNS:
		return dnsv1.ExtendedErrorCodeForgedAnswer
	case ResponseTypeHOSTSFILE:
		return dnsv1.ExtendedErrorCodeForgedAnswer
	case ResponseTypeNOTFQDN:
		return dnsv1.ExtendedErrorCodeBlocked
	case ResponseTypeBLOCKED:
		return dnsv1.ExtendedErrorCodeBlocked
	// RFC 8914: "Blocked" is blocking due to an internal security policy of the
	// operator, "Filtered" is blocking requested by the client. Rebinding
	// protection is operator policy, so it reports as Blocked.
	case ResponseTypeREBIND:
		return dnsv1.ExtendedErrorCodeBlocked
	// EdeResolver sits above the DNSSEC resolver and rewrites the EDE option from
	// the response type, so this must reproduce the code the DNSSEC resolver sets
	// on its SERVFAIL; mapping it to anything else would overwrite Bogus (6).
	case ResponseTypeBOGUS:
		return dnsv1.ExtendedErrorCodeDNSBogus
	case ResponseTypeFILTERED:
		return dnsv1.ExtendedErrorCodeFiltered
	case ResponseTypeSPECIAL:
		return dnsv1.ExtendedErrorCodeFiltered
	case ResponseTypeSYNTHESIZED:
		return dnsv1.ExtendedErrorCodeForgedAnswer
	default:
		return dnsv1.ExtendedErrorCodeOther
	}
}

// Response represents the response of a DNS query
type Response struct {
	Res    *dnsv1.Msg
	Reason string
	// ReasonLabel is a low-cardinality variant of Reason, used as a Prometheus
	// metric label. When empty, metrics fall back to Reason. Blocked responses
	// set this to the matched group names only (without the matched rule), to
	// keep the `reason` label bounded even with large deny lists.
	ReasonLabel string
	RType       ResponseType
}

// RequestProtocol represents the server protocol ENUM(
// TCP // is the TCP protocol
// UDP // is the UDP protocol
// )
type RequestProtocol uint8

// Request represents client's DNS request
type Request struct {
	ClientIP        netip.Addr
	RequestClientID string
	Protocol        RequestProtocol
	ClientNames     []string
	Req             *dnsv1.Msg
	RequestTS       time.Time
}
