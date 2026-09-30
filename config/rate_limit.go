package config

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const (
	ipv4MaxPrefix = 32
	ipv6MaxPrefix = 128
)

// RateLimit configures per-client rate limiting at the head of the resolver chain.
type RateLimit struct {
	// Enable per-client DNS rate limiting.
	Enable bool `default:"false" yaml:"enable"`
	// Sustained query rate limit in queries per second per client.
	Rate uint `default:"0" yaml:"rate"`
	// Token bucket capacity; queries above this burst are dropped. Defaults to rate × 2.
	Burst uint `default:"0" yaml:"burst"`
	// Prefix length used to aggregate IPv4 client addresses into a single bucket.
	IPv4Prefix uint8 `default:"32" yaml:"ipv4Prefix"`
	// Prefix length used to aggregate IPv6 client addresses into a single bucket.
	IPv6Prefix uint8 `default:"64" yaml:"ipv6Prefix"`
	// CIDRs or IPs that are never rate-limited.
	Allowlist []string `yaml:"allowlist"`

	parsedAllowlist []netip.Prefix
}

// IsEnabled implements `config.Configurable`.
func (c *RateLimit) IsEnabled() bool { return c.Enable }

// LogConfig implements `config.Configurable`.
func (c *RateLimit) LogConfig(logger *logrus.Entry) {
	logger.Infof("rate         = %d qps", c.Rate)
	logger.Infof("burst        = %d", c.Burst)
	logger.Infof("ipv4 prefix  = /%d", c.IPv4Prefix)
	logger.Infof("ipv6 prefix  = /%d", c.IPv6Prefix)
	logger.Infof("allowlist    = %v", c.Allowlist)
}

func (c *RateLimit) validate() error {
	if !c.Enable {
		return nil
	}
	if c.Rate == 0 {
		return errors.New("rateLimit: rate must be > 0 when enabled")
	}
	if c.Burst == 0 {
		// Sensible default: allow short spikes of up to 2× the sustained rate.
		c.Burst = c.Rate * 2
	}
	if c.Burst < c.Rate {
		return fmt.Errorf("rateLimit: burst (%d) must be >= rate (%d)", c.Burst, c.Rate)
	}
	if c.IPv4Prefix > ipv4MaxPrefix {
		return fmt.Errorf("rateLimit: ipv4Prefix (%d) must be in [0, %d]", c.IPv4Prefix, ipv4MaxPrefix)
	}
	if c.IPv6Prefix > ipv6MaxPrefix {
		return fmt.Errorf("rateLimit: ipv6Prefix (%d) must be in [0, %d]", c.IPv6Prefix, ipv6MaxPrefix)
	}
	parsed := make([]netip.Prefix, 0, len(c.Allowlist))
	for _, s := range c.Allowlist {
		ipNet, err := parseCIDRorIP(s)
		if err != nil {
			return fmt.Errorf("rateLimit: allowlist entry %q: %w", s, err)
		}
		parsed = append(parsed, ipNet)
	}
	c.parsedAllowlist = parsed

	return nil
}

// ValidateForTest exposes validate for cross-package tests.
// Internal package callers should use the unexported validate.
func (c *RateLimit) ValidateForTest() error { return c.validate() }

// ParsedAllowlist returns the parsed CIDR list populated by validate.
func (c *RateLimit) ParsedAllowlist() []netip.Prefix { return c.parsedAllowlist }

func parseCIDRorIP(s string) (netip.Prefix, error) {
	if prefix, err := util.ParsePrefix(s); err == nil {
		return prefix, nil
	}
	if ip := util.ParseIP(s); ip.IsValid() {
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}

	return netip.Prefix{}, fmt.Errorf("not a valid CIDR or IP: %q", s)
}
