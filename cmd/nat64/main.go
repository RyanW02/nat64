package main

import (
	"flag"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"nat64/pkg/nat64"
	"net"
	"os"
	"os/signal"
	"time"
)

var (
	TunName       = flag.String("tun", "tun0", "Name of the TUN device")
	WanInterface  = flag.String("wan", "eth0", "Name of the WAN interface")
	BufferSize    = flag.Int("buffer", 1500, "Size of the buffer for reading packets - should be the same as the MTU of the TUN device")
	AutoConfigure = flag.Bool("auto-configure", true, "Whether to automatically configure the IP routes and iptables NAT rules")
	NAT4Address   = flag.String("nat4-address", "10.10.10.10", "The RFC1918 IPv4 address to rewrite the NAT4 traffic to. This address will be masqueraded away by iptables.")
	NAT6Prefix    = flag.String("nat6-prefix", "::ffff:0:0:0/96", "The IPv6 prefix to use internally for the NAT6 translation")
)

func main() {
	flag.Parse()

	// Set up logger
	logConfig := zap.NewProductionConfig()
	logConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	logConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logConfig.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.DateTime)
	logConfig.Encoding = "console"

	logger, err := logConfig.Build()
	if err != nil {
		fmt.Println("Error creating logger:", err)
		os.Exit(1)
	}

	// Parse gateway options
	v4Address := net.ParseIP(*NAT4Address)
	if v4Address == nil || v4Address.To4() == nil {
		fmt.Println("Invalid nat4-address: it should be a single RFC1918 IPv4 address")
		os.Exit(2)
	}

	v4Address = v4Address.To4()

	_, v6Prefix, err := net.ParseCIDR(*NAT6Prefix)
	if err != nil {
		fmt.Println("Invalid nat6-prefix: must be a valid IPv6 prefix, of at least /96 length")
		os.Exit(2)
	}

	size, _ := v6Prefix.Mask.Size()
	if size > 96 {
		fmt.Println("Invalid nat6-prefix: prefix length must be at least /96")
		os.Exit(2)
	}

	opts := nat64.Options{
		TunName:          *TunName,
		WANInterfaceName: *WanInterface,
		BufferSize:       *BufferSize,
		AutoConfigure:    *AutoConfigure,
		NAT4Address:      v4Address,
		NAT6Prefix:       v6Prefix,
	}

	// Start NAT64 gateway
	gateway := nat64.NewGateway(opts, logger)

	if opts.AutoConfigure {
		if err := gateway.Configure(); err != nil {
			logger.Fatal("Error configuring NAT64 gateway", zap.Error(err))
		}
	}

	gatewayErrCh := gateway.Run()

	// Wait for interrupt signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt)
	select {
	case err := <-gatewayErrCh:
		logger.Error("NAT64 gateway encountered an error, shutting down", zap.Error(err))
	case <-shutdown:
	}

	if opts.AutoConfigure {
		if err := gateway.Teardown(); err != nil {
			logger.Fatal("Error tearing down NAT64 gateway", zap.Error(err))
		}
	}
}
