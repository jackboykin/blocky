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

	dnsv1 "github.com/miekg/dns"
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
func AnswerToString(answer []dnsv1.RR) string {
	answers := make([]string, len(answer))

	for i, record := range answer {
		switch v := record.(type) {
		case *dnsv1.A:
			answers[i] = fmt.Sprintf("A (%s)", v.A)
		case *dnsv1.AAAA:
			answers[i] = fmt.Sprintf("AAAA (%s)", v.AAAA)
		case *dnsv1.CNAME:
			answers[i] = fmt.Sprintf("CNAME (%s)", v.Target)
		case *dnsv1.PTR:
			answers[i] = fmt.Sprintf("PTR (%s)", v.Ptr)
		default:
			answers[i] = record.String()
		}
	}

	return strings.Join(answers, ", ")
}

// QuestionToString creates a user-friendly representation of a question
func QuestionToString(questions []dnsv1.Question) string {
	result := make([]string, len(questions))
	for i, question := range questions {
		result[i] = fmt.Sprintf("%s (%s)", dnsv1.TypeToString[question.Qtype], question.Name)
	}

	return Obfuscate(strings.Join(result, ", "))
}

// CreateAnswerFromQuestion creates new answer from a question
func CreateAnswerFromQuestion(question dnsv1.Question, ip netip.Addr, remainingTTL uint32) (dnsv1.RR, error) {
	h := CreateHeader(question, remainingTTL)

	switch question.Qtype {
	case dnsv1.TypeA:
		a := new(dnsv1.A)
		a.A = IPFromAddr(ip)
		a.Hdr = h

		return a, nil
	case dnsv1.TypeAAAA:
		a := new(dnsv1.AAAA)
		a.AAAA = IPFromAddr(ip)
		a.Hdr = h

		return a, nil
	}

	log.Log().Errorf("Using fallback for unsupported query type %s", dnsv1.TypeToString[question.Qtype])

	rr, err := dnsv1.NewRR(fmt.Sprintf("%s %d %s %s %s",
		question.Name, remainingTTL, "IN", dnsv1.TypeToString[question.Qtype], ip))
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS RR for type %s: %w", dnsv1.TypeToString[question.Qtype], err)
	}

	return rr, nil
}

// CreateHeader creates DNS header for passed question
func CreateHeader(question dnsv1.Question, remainingTTL uint32) dnsv1.RR_Header {
	return dnsv1.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dnsv1.ClassINET, Ttl: remainingTTL}
}

// CreateSOAForNegativeResponse creates an SOA record for NXDOMAIN responses
// per RFC 2308. The TTL and MINTTL are both set to blockTTL to ensure
// proper negative caching behavior.
func CreateSOAForNegativeResponse(question dnsv1.Question, blockTTL uint32) *dnsv1.SOA {
	// Use the queried domain as the zone name
	zoneName := dnsv1.Fqdn(question.Name)

	return &dnsv1.SOA{
		Hdr: dnsv1.RR_Header{
			Name:   zoneName,
			Rrtype: dnsv1.TypeSOA,
			Class:  dnsv1.ClassINET,
			Ttl:    blockTTL,
		},
		Ns:      "blocky.local.",            // Name server
		Mbox:    "hostmaster.blocky.local.", // Mailbox (admin contact)
		Serial:  1,                          // Serial number
		Refresh: soaRefresh,                 // 24 hours
		Retry:   soaRetry,                   // 2 hours
		Expire:  soaExpire,                  // 7 days
		Minttl:  blockTTL,                   // Negative caching TTL (RFC 2308)
	}
}

// ExtractDomain returns domain string from the question
func ExtractDomain(question dnsv1.Question) string {
	return ExtractDomainOnly(question.Name)
}

// ExtractDomainOnly extracts domain from the DNS query
func ExtractDomainOnly(in string) string {
	return strings.TrimSuffix(strings.ToLower(in), ".")
}

// NewMsgWithQuestion creates new DNS message with question
func NewMsgWithQuestion(question string, qType dnsv1.Type) *dnsv1.Msg {
	msg := new(dnsv1.Msg)
	msg.SetQuestion(dnsv1.Fqdn(question), uint16(qType))

	return msg
}

// NewMsgWithAnswer creates new DNS message with answer
func NewMsgWithAnswer(domain string, ttl uint, dnsType dnsv1.Type, address string) (*dnsv1.Msg, error) {
	rr, err := dnsv1.NewRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", domain, ttl, dnsType, address))
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS RR for domain '%s' (type %s): %w", domain, dnsType, err)
	}

	msg := new(dnsv1.Msg)
	msg.Answer = []dnsv1.RR{rr}

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
func GenerateCacheKey(qType dnsv1.Type, qName string) string {
	const qTypeLength = 2
	b := make([]byte, qTypeLength+len(qName))

	binary.BigEndian.PutUint16(b, uint16(qType))
	copy(b[2:], strings.ToLower(qName))

	return string(b)
}

// ExtractCacheKey return query type/domain from cacheKey
func ExtractCacheKey(key string) (qType dnsv1.Type, qName string) {
	b := []byte(key)

	qType = dnsv1.Type(binary.BigEndian.Uint16(b))
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
func ExtractRecords[T dnsv1.RR](msg *dnsv1.Msg) []T {
	var records []T
	for _, rr := range msg.Answer {
		if record, ok := rr.(T); ok {
			records = append(records, record)
		}
	}

	return records
}

// ExtractRecordsFromSlice extracts all records of type T from a DNS RR slice
func ExtractRecordsFromSlice[T dnsv1.RR](rrs []dnsv1.RR) []T {
	var records []T
	for _, rr := range rrs {
		if record, ok := rr.(T); ok {
			records = append(records, record)
		}
	}

	return records
}
