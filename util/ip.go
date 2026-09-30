package util

import (
	"net"
	"net/netip"
)

// ParseIP parses s the way net.ParseIP does: zoned addresses are rejected and
// IPv4-mapped IPv6 addresses become plain IPv4. The result is invalid if s is
// not an IP.
func ParseIP(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}
	}

	return addr.Unmap()
}

// ParsePrefix parses s the way net.ParseCIDR does: the result is masked and an
// IPv4-mapped IPv6 prefix becomes the plain IPv4 prefix it covers.
func ParsePrefix(s string) (netip.Prefix, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return netip.Prefix{}, err
	}

	addr := AddrFromIP(ipNet.IP)
	ones, bits := ipNet.Mask.Size()

	if addr.Is4() {
		ones -= bits - addr.BitLen()
	}

	return netip.PrefixFrom(addr, ones), nil
}

// AddrFromIP converts ip, unmapping IPv4-mapped IPv6 addresses. The result is
// invalid if ip is not 4 or 16 bytes long.
func AddrFromIP(ip net.IP) netip.Addr {
	addr, _ := netip.AddrFromSlice(ip)

	return addr.Unmap()
}

// IPFromAddr converts addr to the 16-byte form net.ParseIP returns, or nil if
// addr is invalid.
func IPFromAddr(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}

	ip := addr.As16()

	return ip[:]
}
