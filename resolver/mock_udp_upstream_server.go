package resolver

import (
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	dnsv1 "github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
)

type MockUDPUpstreamServer struct {
	callCount atomic.Int32
	ln        *net.UDPConn
	answerFn  func(request *dnsv1.Msg) (response *dnsv1.Msg)
}

func NewMockUDPUpstreamServer() *MockUDPUpstreamServer {
	srv := &MockUDPUpstreamServer{}

	ginkgo.DeferCleanup(srv.Close)

	return srv
}

func (t *MockUDPUpstreamServer) WithAnswerRR(answers ...string) *MockUDPUpstreamServer {
	t.answerFn = rrAnswerFn(answers...)

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerMsg(answer *dnsv1.Msg) *MockUDPUpstreamServer {
	t.answerFn = func(request *dnsv1.Msg) (response *dnsv1.Msg) {
		return answer
	}

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerError(errorCode int) *MockUDPUpstreamServer {
	t.answerFn = errorAnswerFn(errorCode)

	return t
}

func (t *MockUDPUpstreamServer) WithAnswerFn(fn func(request *dnsv1.Msg) (response *dnsv1.Msg)) *MockUDPUpstreamServer {
	t.answerFn = fn

	return t
}

func (t *MockUDPUpstreamServer) WithDelay(delay time.Duration) *MockUDPUpstreamServer {
	answerFn := t.answerFn
	if answerFn == nil {
		panic("WithDelay must be called after a WithAnswer function")
	}

	t.answerFn = func(request *dnsv1.Msg) *dnsv1.Msg {
		time.Sleep(delay)

		return answerFn(request)
	}

	return t
}

func (t *MockUDPUpstreamServer) GetCallCount() int {
	return int(t.callCount.Load())
}

func (t *MockUDPUpstreamServer) ResetCallCount() {
	t.callCount.Store(0)
}

func (t *MockUDPUpstreamServer) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

func createConnection() *net.UDPConn {
	a, err := net.ResolveUDPAddr("udp4", ":0")
	util.FatalOnError("can't resolve address: ", err)

	ln, err := net.ListenUDP("udp4", a)
	util.FatalOnError("can't create connection: ", err)

	return ln
}

func (t *MockUDPUpstreamServer) Start() config.Upstream {
	ln := createConnection()

	ladr := ln.LocalAddr().String()
	host := strings.Split(ladr, ":")[0]
	p, err := config.ConvertPort(strings.Split(ladr, ":")[1])

	util.FatalOnError("can't convert port: ", err)

	port := p
	t.ln = ln

	go func() {
		const bufferSize = 1024

		for {
			buffer := make([]byte, bufferSize)

			n, addr, err := ln.ReadFromUDP(buffer)
			if err != nil {
				// closed
				break
			}

			go func() {
				defer ginkgo.GinkgoRecover()
				msg := new(dnsv1.Msg)
				err = msg.Unpack(buffer[0:n])

				util.FatalOnError("can't deserialize message: ", err)

				response := t.answerFn(msg)

				t.callCount.Add(1)
				// nil should indicate an error
				if response == nil {
					_, _ = ln.WriteToUDP([]byte("dummy"), addr)

					return
				}

				b, err := mockReply(msg, response).Pack()
				util.FatalOnError("can't serialize message: ", err)

				_, _ = ln.WriteToUDP(b, addr)
			}()
		}
	}()

	return config.Upstream{Net: config.NetProtocolTcpUdp, Host: host, Port: port}
}
