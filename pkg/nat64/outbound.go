package nat64

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"golang.org/x/net/ipv6"
)

func (g *Gateway) handleOutboundPacket(bytes []byte) {
	logger := g.logger.With(zap.String("flow", "outbound"))

	if len(bytes) < ipv6.HeaderLen {
		logger.Warn("Packet too short to contain header", zap.Any("bytes", bytes))
		return
	}

	packet := gopacket.NewPacket(bytes, layers.LayerTypeIPv6, gopacket.Default)
	if packet.NetworkLayer() == nil || packet.NetworkLayer().LayerType() != layers.LayerTypeIPv6 {
		logger.Warn("Packet does not contain an IPv6 layer")
		return
	}

	v6Header := packet.NetworkLayer().(*layers.IPv6)
	data := v6Header.LayerPayload()

	v4Dst := v6Header.DstIP[12:16]
	v4Src := v6Header.SrcIP[12:16]

	if v4Dst.IsPrivate() {
		return
	}

	v4Header := &layers.IPv4{
		BaseLayer: layers.BaseLayer{
			Contents: nil,
			Payload:  data,
		},
		Version:    4,
		IHL:        0,
		TOS:        v6Header.TrafficClass,
		Length:     0, // Computed upon serialization
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        v6Header.HopLimit,
		Protocol:   v6Header.NextHeader,
		Checksum:   0, // Computed upon serialization
		SrcIP:      v4Src,
		DstIP:      v4Dst,
		Options:    nil,
		Padding:    nil,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for _, hook := range g.outboundHooks[uint8(v4Header.Protocol)] {
		mutated, forward := hook(v4Header, data)
		if !forward {
			logger.Debug("Outbound hook dropped packet", zap.Any("header", v6Header))
			return
		}

		if mutated != nil {
			data = mutated
		}
	}

	if err := gopacket.SerializeLayers(buf, opts, v4Header, gopacket.Payload(data)); err != nil {
		logger.Error("Error serializing IPv4 packet", zap.Error(err), zap.Any("header", v4Header))
		return
	}

	if _, err := g.iface.Write(buf.Bytes()); err != nil {
		logger.Error("Error writing packet to TUN interface", zap.Error(err), zap.Any("header", v4Header))
		return
	}

	logger.Debug(
		"Packet sent to TUN interface",
		zap.String("v6_src", v6Header.SrcIP.String()),
		zap.String("v6_dst", v6Header.DstIP.String()),
		zap.String("v4_src", v4Src.String()),
		zap.String("v4_dst", v4Dst.String()),
	)
}
