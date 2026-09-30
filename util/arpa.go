package util

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const (
	IPv4PtrSuffix = ".in-addr.arpa."
	IPv6PtrSuffix = ".ip6.arpa."

	byteBits = 8
)

var ErrInvalidArpaAddrLen = errors.New("arpa hostname is not of expected length")

func ParseIPFromArpaAddr(arpa string) (netip.Addr, error) {
	if strings.HasSuffix(arpa, IPv4PtrSuffix) {
		return parseIPv4FromArpaAddr(arpa)
	}

	if strings.HasSuffix(arpa, IPv6PtrSuffix) {
		return parseIPv6FromArpaAddr(arpa)
	}

	return netip.Addr{}, fmt.Errorf("invalid arpa hostname: %s", arpa)
}

func parseIPv4FromArpaAddr(arpa string) (netip.Addr, error) {
	const base10 = 10

	revAddr := strings.TrimSuffix(arpa, IPv4PtrSuffix)

	parts := strings.Split(revAddr, ".")
	if len(parts) != net.IPv4len {
		return netip.Addr{}, ErrInvalidArpaAddrLen
	}

	buf := make([]byte, 0, net.IPv4len)

	// Parse and add each byte, in reverse, to the buffer
	for _, part := range slices.Backward(parts) {
		p, err := strconv.ParseUint(part, base10, byteBits)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to parse IPv4 octet '%s' in arpa address '%s': %w", part, arpa, err)
		}

		buf = append(buf, byte(p))
	}

	return netip.AddrFrom4([net.IPv4len]byte(buf)), nil
}

func parseIPv6FromArpaAddr(arpa string) (netip.Addr, error) {
	const (
		base16     = 16
		ipv6Bytes  = 2 * net.IPv6len
		nibbleBits = byteBits / 2
	)

	revAddr := strings.TrimSuffix(arpa, IPv6PtrSuffix)

	parts := strings.Split(revAddr, ".")
	if len(parts) != ipv6Bytes {
		return netip.Addr{}, ErrInvalidArpaAddrLen
	}

	buf := make([]byte, 0, net.IPv6len)

	// Parse and add each byte, in reverse, to the buffer
	for i := len(parts) - 1; i >= 0; i -= 2 {
		msNibble, err := strconv.ParseUint(parts[i], base16, byteBits)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to parse IPv6 nibble '%s' in arpa address '%s': %w", parts[i], arpa, err)
		}

		lsNibble, err := strconv.ParseUint(parts[i-1], base16, byteBits)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to parse IPv6 nibble '%s' in arpa address '%s': %w", parts[i-1], arpa, err)
		}

		part := msNibble<<nibbleBits | lsNibble

		buf = append(buf, byte(part)) //nolint:gosec // nibble values always fit in a byte
	}

	// Unmap so an IPv4-mapped name yields the same address as its in-addr.arpa form.
	return netip.AddrFrom16([net.IPv6len]byte(buf)).Unmap(), nil
}
