package config

import (
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
)

// ClientLookup configuration for the client lookup
type ClientLookup struct {
	// Static map of client name to one or more IP addresses for manual client name assignment.
	ClientnameIPMapping map[string][]netip.Addr `yaml:"clients"`
	// Upstream DNS server used for rDNS client name lookups (typically your router).
	Upstream Upstream `yaml:"upstream"`
	// Order of preference when a router returns multiple names for a client (1-based index).
	SingleNameOrder []uint `yaml:"singleNameOrder"`
}

func (c *ClientLookup) UnmarshalYAML(unmarshal func(any) error) error {
	// clientLookup is used to avoid infinite recursion.
	type clientLookup ClientLookup

	if err := unmarshal((*clientLookup)(c)); err != nil {
		return err
	}

	for name, ips := range c.ClientnameIPMapping {
		if err := normalizeIPs(ips); err != nil {
			return fmt.Errorf("client '%s': %w", name, err)
		}
	}

	return nil
}

// IsEnabled implements `config.Configurable`.
func (c *ClientLookup) IsEnabled() bool {
	return !c.Upstream.IsDefault() || len(c.ClientnameIPMapping) != 0
}

// LogConfig implements `config.Configurable`.
func (c *ClientLookup) LogConfig(logger *logrus.Entry) {
	if !c.Upstream.IsDefault() {
		logger.Infof("upstream = %s", c.Upstream)
	}

	logger.Infof("singleNameOrder = %v", c.SingleNameOrder)

	if len(c.ClientnameIPMapping) > 0 {
		logger.Infof("client IP mapping:")

		for k, v := range c.ClientnameIPMapping {
			logger.Infof("  %s = %s", k, v)
		}
	}
}
