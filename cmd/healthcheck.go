package cmd

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/spf13/cobra"
)

const (
	defaultDNSPort     = 53
	defaultIPAddress   = "127.0.0.1"
	healthcheckTimeout = 2 * time.Second
)

func NewHealthcheckCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "healthcheck",
		Short: "performs healthcheck",
		// Load the configuration like every other subcommand, so the defaults below can
		// follow `ports.dns`. A missing or unreadable config must not break the
		// healthcheck: it then keeps working with the flag defaults, exactly as before.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			_ = args
			_ = initConfig()

			return nil
		},
		RunE: healthcheck,
	}

	c.Flags().Uint16P("port", "p", defaultDNSPort, "blocky port")
	c.Flags().StringP("bindip", "b", defaultIPAddress, "blocky host binding ip address")

	return c
}

func healthcheck(cmd *cobra.Command, args []string) error {
	_ = args
	port, _ := cmd.Flags().GetUint16("port")
	bindIP, _ := cmd.Flags().GetString("bindip")

	// An explicitly given flag always wins; otherwise follow the loaded configuration.
	if !cmd.Flags().Changed("port") {
		port = dnsPort
	}

	if !cmd.Flags().Changed("bindip") {
		bindIP = dnsHost
	}

	c := &dns.Client{Transport: &dns.Transport{
		Dialer:       &net.Dialer{Timeout: healthcheckTimeout},
		ReadTimeout:  healthcheckTimeout,
		WriteTimeout: healthcheckTimeout,
	}}
	m := dns.NewMsg("healthcheck.blocky.", dns.TypeA)

	addr := net.JoinHostPort(bindIP, strconv.FormatUint(uint64(port), 10))
	_, _, err := c.Exchange(cmd.Context(), m, "tcp", addr)

	if err == nil {
		fmt.Println("OK")
	} else {
		fmt.Println("NOT OK")

		return fmt.Errorf("healthcheck failed for %s: %w", addr, err)
	}

	return nil
}
