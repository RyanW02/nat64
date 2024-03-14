package nat64

import (
	"github.com/songgao/water"
	"go.uber.org/zap"
	"net"
	"os/exec"
)

type Gateway struct {
	options       Options
	logger        *zap.Logger
	outboundHooks map[uint8][]OutboundHook
	inboundHooks  map[uint8][]InboundHook

	iface *water.Interface
}

type Options struct {
	TunName          string
	WANInterfaceName string
	BufferSize       int
	AutoConfigure    bool
	NAT4Address      net.IP
	NAT6Prefix       *net.IPNet
}

func NewGateway(options Options, logger *zap.Logger) *Gateway {
	return &Gateway{
		options: options,
		logger:  logger,
	}
}

func (g *Gateway) Configure() error {
	iface, err := g.createTUN()
	if err != nil {
		return err
	}

	g.iface = iface

	g.logger.Info("Configuring NAT64 gateway")
	return NewCommandSet(
		// Set link to UP state
		NewCommand(exec.Command("/bin/ip", "link", "set", "dev", g.options.TunName, "up")),

		// Configure routes
		// If the route already exists, /bin/ip will exit with status code 2 - accept this as a valid exit code
		NewCommand(exec.Command("/bin/ip", "-6", "route", "add", "64:ff9b::/96", "dev", g.options.TunName), 2),
		NewCommand(exec.Command("/bin/ip", "-6", "route", "add", g.options.NAT6Prefix.String(), "dev", g.options.TunName), 2),
		NewCommand(exec.Command("/bin/ip", "route", "add", g.options.NAT4Address.String(), "dev", g.options.TunName), 2),

		// Set up NAT masquerading
		NewCommand(exec.Command("/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1")),
		NewCommand(exec.Command("/usr/sbin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", g.options.WANInterfaceName, "-j", "MASQUERADE")),
		NewCommand(exec.Command("/usr/sbin/ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", g.options.TunName, "-j", "SNAT", "--to-source", g.nat6Address().String())),
	).Run(g.logger)
}

func (g *Gateway) Teardown() error {
	g.logger.Info("Tearing down NAT64 gateway")
	return NewCommandSet(
		// Remove routes
		NewCommand(exec.Command("/bin/ip", "-6", "route", "del", "64:ff9b::/96", "dev", g.options.TunName)),
		NewCommand(exec.Command("/bin/ip", "-6", "route", "del", g.options.NAT6Prefix.String(), "dev", g.options.TunName)),
		NewCommand(exec.Command("/bin/ip", "route", "del", g.options.NAT4Address.String(), "dev", g.options.TunName)),

		// Remove NAT masquerading
		NewCommand(exec.Command("/usr/sbin/iptables", "-t", "nat", "-D", "POSTROUTING", "-o", g.options.WANInterfaceName, "-j", "MASQUERADE")),
		NewCommand(exec.Command("/usr/sbin/ip6tables", "-t", "nat", "-D", "POSTROUTING", "-o", g.options.TunName, "-j", "SNAT", "--to-source", g.nat6Address().String())),

		// Delete the TUN device
		NewCommand(exec.Command("/bin/ip", "link", "delete", g.options.TunName)),
	).Run(g.logger)
}

func (g *Gateway) RegisterOutboundHook(protocol uint8, hook OutboundHook) {
	if g.outboundHooks == nil {
		g.outboundHooks = make(map[uint8][]OutboundHook)
	}

	g.outboundHooks[protocol] = append(g.outboundHooks[protocol], hook)
}

func (g *Gateway) RegisterInboundHook(protocol uint8, hook InboundHook) {
	if g.inboundHooks == nil {
		g.inboundHooks = make(map[uint8][]InboundHook)
	}

	g.inboundHooks[protocol] = append(g.inboundHooks[protocol], hook)
}

func (g *Gateway) Run() chan error {
	shutdownCh := make(chan error)

	go func(shutdownCh chan error) {
		if g.iface == nil {
			iface, err := g.createTUN()
			if err != nil {
				shutdownCh <- err
				return
			}

			g.iface = iface
		}

		g.logger.Info("Starting NAT64 gateway")

		bytes := make([]byte, g.options.BufferSize)
		for {
			n, err := g.iface.Read(bytes)
			if err != nil {
				shutdownCh <- err
				return
			}

			ipVersion := bytes[0] >> 4
			if ipVersion == 6 {
				g.handleOutboundPacket(bytes[:n])
			} else {
				g.handleInboundPacket(bytes[:n])
			}
		}
	}(shutdownCh)

	return shutdownCh
}

func (g *Gateway) createTUN() (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: g.options.TunName,
		},
	}

	g.logger.Info("Creating TUN device", zap.String("tun_name", g.options.TunName))

	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}

	return iface, nil
}

func (g *Gateway) nat6Address() net.IP {
	addr := make(net.IP, 16)
	copy(addr, g.options.NAT6Prefix.IP)

	addr[12] = g.options.NAT4Address[0]
	addr[13] = g.options.NAT4Address[1]
	addr[14] = g.options.NAT4Address[2]
	addr[15] = g.options.NAT4Address[3]
	return addr
}
