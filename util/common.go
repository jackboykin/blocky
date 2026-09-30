package util

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/0xERR0R/blocky/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/sirupsen/logrus"
)

//nolint:gochecknoglobals
var (
	// To avoid making this package depend on config, we use a global
	// that is set at config load.
	// Ideally we'd move the obfuscate code somewhere else (maybe into `log`),
	// but that would require also moving all its dependencies.
	// This is good enough for now.
	LogPrivacy atomic.Bool

	alphanumeric = regexp.MustCompile("[a-zA-Z0-9]")
)

// SOA record timing defaults for negative responses (RFC 2308)
const (
	soaRefresh = 86400  // 24 hours
	soaRetry   = 7200   // 2 hours
	soaExpire  = 604800 // 7 days
)

// Obfuscate replaces all alphanumeric characters with * to obfuscate user sensitive data if LogPrivacy is enabled
func Obfuscate(in string) string {
	if LogPrivacy.Load() {
		return alphanumeric.ReplaceAllString(in, "*")
	}

	return in
}

// AnswerToString creates a user-friendly representation of an answer.
// The result is NOT obfuscated; callers that emit it to logs must wrap with Obfuscate.
func AnswerToString(answer []dns.RR) string {
	answers := make([]string, len(answer))

	for i, record := range answer {
		switch v := record.(type) {
		case *dns.A:
			answers[i] = fmt.Sprintf("A (%s)", v.Addr)
		case *dns.AAAA:
			answers[i] = fmt.Sprintf("AAAA (%s)", v.Addr)
		case *dns.CNAME:
			answers[i] = fmt.Sprintf("CNAME (%s)", v.Target)
		case *dns.PTR:
			answers[i] = fmt.Sprintf("PTR (%s)", v.Ptr)
		default:
			answers[i] = record.String()
		}
	}

	return strings.Join(answers, ", ")
}

// QuestionToString creates a user-friendly representation of a question
func QuestionToString(questions []dns.RR) string {
	result := make([]string, len(questions))
	for i, question := range questions {
		result[i] = fmt.Sprintf("%s (%s)", dnsutil.TypeToString(dns.RRToType(question)), question.Header().Name)
	}

	return Obfuscate(strings.Join(result, ", "))
}

// NewQuestion creates the question section entry for name and qType. Unlike dns.NewMsg it
// accepts types the dns package has no struct for, the way it unpacks them: as RFC3597.
func NewQuestion(name string, qType uint16) dns.RR {
	hdr := dns.Header{Name: name, Class: dns.ClassINET}

	newFn, ok := dns.TypeToRR[qType]
	if !ok {
		return &dns.RFC3597{Hdr: hdr, RRType: qType}
	}

	rr := newFn()
	*rr.Header() = hdr

	return rr
}

// CreateAnswerFromQuestion creates new answer from a question
func CreateAnswerFromQuestion(question dns.RR, ip netip.Addr, remainingTTL uint32) (dns.RR, error) {
	h := CreateHeader(question, remainingTTL)
	qType := dns.RRToType(question)

	switch qType {
	case dns.TypeA:
		return &dns.A{Hdr: h, Addr: ip}, nil
	case dns.TypeAAAA:
		return &dns.AAAA{Hdr: h, Addr: ip}, nil
	}

	log.Log().Errorf("Using fallback for unsupported query type %s", dnsutil.TypeToString(qType))

	rr, err := newRR(fmt.Sprintf("%s %d %s %s %s",
		h.Name, remainingTTL, "IN", dnsutil.TypeToString(qType), ip))
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS RR for type %s: %w", dnsutil.TypeToString(qType), err)
	}

	return rr, nil
}

// newRR parses the record s like dns.New, and also refuses an owner name that can't be packed,
// which dns.New leaves to packing.
func newRR(s string) (dns.RR, error) {
	rr, err := dns.New(s)
	if err != nil {
		return nil, err
	}

	if name := rr.Header().Name; !dnsutil.IsName(name) {
		return nil, fmt.Errorf("invalid owner name %q", name)
	}

	return rr, nil
}

// CreateHeader creates DNS header for passed question
func CreateHeader(question dns.RR, remainingTTL uint32) dns.Header {
	return dns.Header{Name: question.Header().Name, Class: dns.ClassINET, TTL: remainingTTL}
}

// CreateSOAForNegativeResponse creates an SOA record for NXDOMAIN responses
// per RFC 2308. The TTL and MINTTL are both set to blockTTL to ensure
// proper negative caching behavior.
func CreateSOAForNegativeResponse(question dns.RR, blockTTL uint32) *dns.SOA {
	return &dns.SOA{
		// Use the queried domain as the zone name
		Hdr: dns.Header{Name: dnsutil.Fqdn(question.Header().Name), Class: dns.ClassINET, TTL: blockTTL},
		SOA: rdata.SOA{
			Ns:      "blocky.local.",            // Name server
			Mbox:    "hostmaster.blocky.local.", // Mailbox (admin contact)
			Serial:  1,                          // Serial number
			Refresh: soaRefresh,                 // 24 hours
			Retry:   soaRetry,                   // 2 hours
			Expire:  soaExpire,                  // 7 days
			Minttl:  blockTTL,                   // Negative caching TTL (RFC 2308)
		},
	}
}

// ExtractDomain returns domain string from the question
func ExtractDomain(question dns.RR) string {
	return ExtractDomainOnly(question.Header().Name)
}

// ExtractDomainOnly extracts domain from the DNS query
func ExtractDomainOnly(in string) string {
	return strings.TrimSuffix(strings.ToLower(in), ".")
}

// NewMsgWithQuestion creates new DNS message with question
func NewMsgWithQuestion(question string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.RecursionDesired = true
	msg.Question = []dns.RR{NewQuestion(dnsutil.Fqdn(question), qType)}

	return msg
}

// NewMsgWithAnswer creates new DNS message with answer
func NewMsgWithAnswer(domain string, ttl uint, dnsType uint16, address string) (*dns.Msg, error) {
	typeName := dnsutil.TypeToString(dnsType)

	rr, err := newRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", domain, ttl, typeName, address))
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS RR for domain '%s' (type %s): %w", domain, typeName, err)
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rr}

	return msg, nil
}

type kv struct {
	key   string
	value int
}

// IterateValueSorted iterates over maps value in a sorted order and applies the passed function
func IterateValueSorted(in map[string]int, fn func(string, int)) {
	ss := make([]kv, 0, len(in))

	for k, v := range in {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].value > ss[j].value || (ss[i].value == ss[j].value && ss[i].key > ss[j].key)
	})

	for _, kv := range ss {
		fn(kv.key, kv.value)
	}
}

// LogOnError logs the message only if error is not nil
func LogOnError(ctx context.Context, message string, err error) {
	if err != nil {
		log.FromCtx(ctx).Error(message, err)
	}
}

// LogOnErrorWithEntry logs the message only if error is not nil
func LogOnErrorWithEntry(logEntry *logrus.Entry, message string, err error) {
	if err != nil {
		logEntry.Error(message, err)
	}
}

// FatalOnError logs the message only if error is not nil and exits the program execution
func FatalOnError(message string, err error) {
	if err != nil {
		logger := log.Log()

		// Make sure the error is printend even if the log has been silenced
		if logger.Out == io.Discard {
			log.ConfigureLogger(logger, log.DefaultConfig())
		}

		logger.Fatal(message, err)
	}
}

// GenerateCacheKey return cacheKey by query type/domain
func GenerateCacheKey(qType uint16, qName string) string {
	const qTypeLength = 2
	b := make([]byte, qTypeLength+len(qName))

	binary.BigEndian.PutUint16(b, qType)
	copy(b[2:], strings.ToLower(qName))

	return string(b)
}

// ExtractCacheKey return query type/domain from cacheKey
func ExtractCacheKey(key string) (qType uint16, qName string) {
	b := []byte(key)

	qType = binary.BigEndian.Uint16(b)
	qName = string(b[2:])

	return qType, qName
}

// CidrContainsIP checks if CIDR contains a single IP
func CidrContainsIP(cidr string, ip netip.Addr) bool {
	prefix, err := ParsePrefix(cidr)
	if err != nil {
		return false
	}

	return prefix.Contains(ip)
}

// ClientNameMatchesGroupName checks if a group with optional wildcards contains a client name
func ClientNameMatchesGroupName(group, clientName string) bool {
	match, _ := filepath.Match(strings.ToLower(group), strings.ToLower(clientName))

	return match
}

// ExtractRecords extracts all records of type T from a DNS message's Answer section
func ExtractRecords[T dns.RR](msg *dns.Msg) []T {
	var records []T
	for _, rr := range msg.Answer {
		if record, ok := rr.(T); ok {
			records = append(records, record)
		}
	}

	return records
}

// ExtractRecordsFromSlice extracts all records of type T from a DNS RR slice
func ExtractRecordsFromSlice[T dns.RR](rrs []dns.RR) []T {
	var records []T
	for _, rr := range rrs {
		if record, ok := rr.(T); ok {
			records = append(records, record)
		}
	}

	return records
}
