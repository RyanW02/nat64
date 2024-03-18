package nat64

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"nat64/internal"
	"net"
)

func (g *Gateway) handleInboundPacket(bytes []byte) {
	logger := g.logger.With(zap.String("flow", "inbound"))

	if len(bytes) < ipv4.HeaderLen {
		logger.Warn("Packet too short to contain header", zap.Any("bytes", bytes))
		return
	}

	packet := gopacket.NewPacket(bytes, layers.LayerTypeIPv4, gopacket.Default)

	if packet.NetworkLayer() == nil || packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
		logger.Warn("Packet does not contain an IPv4 layer")
		return
	}

	v4Header := packet.NetworkLayer().(*layers.IPv4)
	data := v4Header.LayerPayload()

	if v4Header.SrcIP.IsPrivate() {
		return
	}

	v6Src := internal.IPv4ToNAT64(v4Header.SrcIP)

	v6Dst := make(net.IP, 16)
	copy(v6Dst, g.options.NAT6Prefix.IP)
	copy(v6Dst[12:], v4Header.DstIP.To4())

	v6Header := &layers.IPv6{
		BaseLayer: layers.BaseLayer{
			Contents: nil,
			Payload:  data,
		},
		Version:      6,
		TrafficClass: v4Header.TOS,
		FlowLabel:    0,
		Length:       0,
		NextHeader:   v4Header.Protocol,
		HopLimit:     v4Header.TTL,
		SrcIP:        v6Src,
		DstIP:        v6Dst,
		HopByHop:     nil,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for _, hook := range g.inboundHooks[uint8(v4Header.Protocol)] {
		mutated, forward := hook(v6Header, data)
		if !forward {
			logger.Debug("Inbound hook dropped packet", zap.Any("header", v6Header))
			return
		}

		if mutated != nil {
			data = mutated
		}
	}

	if err := gopacket.SerializeLayers(buf, opts, v6Header, gopacket.Payload(data)); err != nil {
		logger.Error("Error serializing packet", zap.Error(err))
		return
	}

	if _, err := g.iface.Write(buf.Bytes()); err != nil {
		logger.Error("Error writing packet", zap.Error(err))
		return
	}
}
