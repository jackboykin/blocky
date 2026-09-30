package helpertest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"

	"codeberg.org/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/gcustom"
	"github.com/onsi/gomega/types"
)

const (
	A     = dns.TypeA
	AAAA  = dns.TypeAAAA
	CNAME = dns.TypeCNAME
	HTTPS = dns.TypeHTTPS
	MX    = dns.TypeMX
	PTR   = dns.TypePTR
	SRV   = dns.TypeSRV
	TXT   = dns.TypeTXT
	DS    = dns.TypeDS
)

// GetIntPort returns a port for the current testing
// process by adding the current ginkgo parallel process to
// the base port and returning it as int.
func GetIntPort(port int) int {
	return port + ginkgo.GinkgoParallelProcess()
}

// GetStringPort returns a port for the current testing
// process by adding the current ginkgo parallel process to
// the base port and returning it as string.
func GetStringPort(port int) string {
	return strconv.Itoa(GetIntPort(port))
}

// GetHostPort returns a host:port string for the current testing
// process by adding the current ginkgo parallel process to
// the base port and returning it as string.
func GetHostPort(host string, port int) string {
	return net.JoinHostPort(host, GetStringPort(port))
}

// TempFile creates temp file with passed data
func TempFile(data string) *os.File {
	f, err := os.CreateTemp("", "prefix")
	if err != nil {
		log.Log().Fatal(err)
	}

	_, err = f.WriteString(data)
	if err != nil {
		log.Log().Fatal(err)
	}

	return f
}

// TestServer creates temp http server with passed data
func TestServer(data string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := rw.Write([]byte(data))
		if err != nil {
			log.Log().Fatal("can't write to buffer:", err)
		}
	}))

	ginkgo.DeferCleanup(srv.Close)

	return srv
}

// DoGetRequest performs a GET request
func DoGetRequest(ctx context.Context, url string,
	fn func(w http.ResponseWriter, r *http.Request),
) (*httptest.ResponseRecorder, *bytes.Buffer) {
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(fn)

	handler.ServeHTTP(rr, r)

	return rr, rr.Body
}

func ToAnswer(m *model.Response) []dns.RR {
	return m.Res.Answer
}

func ToExtra(m *model.Response) []dns.RR {
	return m.Res.Extra
}

func ToAuthority(m *model.Response) []dns.RR {
	return m.Res.Ns
}

func HaveNoAnswer() types.GomegaMatcher {
	return gomega.WithTransform(ToAnswer, gomega.BeEmpty())
}

func HaveAuthority() types.GomegaMatcher {
	return gomega.WithTransform(ToAuthority, gomega.Not(gomega.BeEmpty()))
}

func HaveSOARecord(ttl, minTTL uint32) types.GomegaMatcher {
	return gcustom.MakeMatcher(func(m *model.Response) (bool, error) {
		if len(m.Res.Ns) == 0 {
			return false, errors.New("no authority section records")
		}

		for _, rr := range m.Res.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				if soa.Header().TTL != ttl {
					return false, fmt.Errorf("SOA TTL is %d, expected %d", soa.Header().TTL, ttl)
				}

				if soa.Minttl != minTTL {
					return false, fmt.Errorf("SOA MINTTL is %d, expected %d", soa.Minttl, minTTL)
				}

				// Verify basic structure
				if soa.Ns == "" || soa.Mbox == "" {
					return false, errors.New("SOA record has empty nameserver or mailbox")
				}

				return true, nil
			}
		}

		return false, errors.New("no SOA record found in authority section")
	}).WithTemplate(
		"Expected:\n{{.Actual}}\n{{.To}} have SOA record with TTL={{index .Data 0}} and MINTTL={{index .Data 1}}",
		ttl, minTTL,
	)
}

func HaveReason(reason string) types.GomegaMatcher {
	return gcustom.MakeMatcher(func(m *model.Response) (bool, error) {
		return m.Reason == reason, nil
	}).WithTemplate(
		"Expected:\n{{.Actual}}\n{{.To}} have reason:\n{{format .Data 1}}",
		reason,
	)
}

func HaveReasonLabel(reasonLabel string) types.GomegaMatcher {
	return gcustom.MakeMatcher(func(m *model.Response) (bool, error) {
		return m.ReasonLabel == reasonLabel, nil
	}).WithTemplate(
		"Expected:\n{{.Actual}}\n{{.To}} have reason label:\n{{format .Data 1}}",
		reasonLabel,
	)
}

func HaveResponseType(c model.ResponseType) types.GomegaMatcher {
	return gcustom.MakeMatcher(func(m *model.Response) (bool, error) {
		return m.RType == c, nil
	}).WithTemplate(
		"Expected:\n{{.Actual}}\n{{.To}} have ResponseType:\n{{format .Data 1}}",
		c.String(),
	)
}

func HaveReturnCode(code uint16) types.GomegaMatcher {
	return gcustom.MakeMatcher(func(m *model.Response) (bool, error) {
		return m.Res.Rcode == code, nil
	}).WithTemplate(
		"Expected:\n{{.Actual}}\n{{.To}} have RCode:\n{{format .Data 1}}",
		fmt.Sprintf("%d (%s)", code, dns.RcodeToString[code]),
	)
}

// HaveEdnsOption checks if the given message contains an EDNS0 record with the given option code.
func HaveEdnsOption(code uint16) types.GomegaMatcher {
	return gcustom.MakeMatcher(func(actual any) (bool, error) {
		var msg *dns.Msg
		switch m := actual.(type) {
		case *model.Response:
			msg = m.Res
		case *dns.Msg:
			msg = m
		default:
			return false, nil
		}

		return slices.ContainsFunc(msg.Pseudo, func(o dns.RR) bool {
			e, ok := o.(dns.EDNS0)

			return ok && dns.RRToCode(e) == code
		}), nil
	}).WithTemplate(
		"Expected:\n{{.Actual}}\n{{.To}} have EDNS option:\n{{format .Data 1}}",
		code,
	)
}

func HaveTTL(matcher types.GomegaMatcher) types.GomegaMatcher {
	return gomega.WithTransform(func(actual any) (uint32, error) {
		// Handle different types of input
		var records []dns.RR

		switch i := actual.(type) {
		case *model.Response:
			records = i.Res.Answer
		case *dns.Msg:
			records = i.Answer
		case []dns.RR:
			records = i
		case dns.RR:
			records = []dns.RR{i}
		default:
			return 0, fmt.Errorf("unsupported type for TTL matching: %T", actual)
		}

		// No records to match
		if len(records) == 0 {
			return 0, errors.New("answer must not be empty")
		}

		// Return TTL of the first record
		// This is a reasonable approach since typically all records in a response
		// have the same TTL, and we're usually testing against a specific expected value
		return records[0].Header().TTL, nil
	}, matcher)
}

// BeDNSRecord returns new dns matcher
func BeDNSRecord(domain string, dnsType uint16, answer string) types.GomegaMatcher {
	return &dnsRecordMatcher{
		domain:  domain,
		dnsType: dnsType,
		answer:  answer,
	}
}

type dnsRecordMatcher struct {
	domain  string
	dnsType uint16
	answer  string
}

func (matcher *dnsRecordMatcher) matchSingle(rr dns.RR) bool {
	if (rr.Header().Name != matcher.domain) ||
		(dns.RRToType(rr) != matcher.dnsType) {
		return false
	}

	switch v := rr.(type) {
	case *dns.A:
		return v.Addr.String() == matcher.answer
	case *dns.AAAA:
		addr, err := netip.ParseAddr(matcher.answer)

		return err == nil && v.Addr == addr
	case *dns.CNAME:
		return v.Target == matcher.answer
	case *dns.PTR:
		return v.Ptr == matcher.answer
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target) == matcher.answer
	case *dns.TXT:
		return strings.Join(v.Txt, " ") == matcher.answer
	case *dns.MX:
		return v.Mx == matcher.answer
	}

	return false
}

// Match checks the DNS record
func (matcher *dnsRecordMatcher) Match(actual any) (success bool, err error) {
	// Handle different types of input
	var records []dns.RR

	switch i := actual.(type) {
	case *model.Response:
		records = i.Res.Answer
	case *dns.Msg:
		records = i.Answer
	case []dns.RR:
		records = i
	case dns.RR:
		records = []dns.RR{i}
	default:
		return false, fmt.Errorf("unsupported type for DNS record matching: %T", actual)
	}

	// No records to match
	if len(records) == 0 {
		return false, nil
	}

	// Try to match any of the records
	for _, rr := range records {
		if match := matcher.matchSingle(rr); match {
			return true, nil
		}
	}

	return false, nil
}

// FailureMessage generates a failure message
func (matcher *dnsRecordMatcher) FailureMessage(actual any) (message string) {
	return fmt.Sprintf("Expected\n\t%s\n to contain\n\t domain '%s', type '%s', answer '%s'",
		actual, matcher.domain, dns.TypeToString[matcher.dnsType], matcher.answer)
}

// NegatedFailureMessage creates negated message
func (matcher *dnsRecordMatcher) NegatedFailureMessage(actual any) (message string) {
	return fmt.Sprintf("Expected\n\t%s\n not to contain\n\t domain '%s', type '%s', answer '%s'",
		actual, matcher.domain, dns.TypeToString[matcher.dnsType], matcher.answer)
}
