package nat64

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"golang.org/x/net/ipv6"
)

type OutboundHook func(header *layers.IPv4, data []byte)

func (g *Gateway) handleOutboundPacket(bytes []byte) {
	logger := g.logger.With(zap.String("flow", "outbound"))

	if len(bytes) < ipv6.HeaderLen {
		logger.Warn("Packet too short to contain header", zap.Any("bytes", bytes))
		return
	}

	v6Header, err := ipv6.ParseHeader(bytes)
	if err != nil {
		logger.Warn("Error parsing IPv6 header", zap.Error(err), zap.Any("bytes", bytes))
		return
	}

	data := bytes[ipv6.HeaderLen:]

	v4Dst := v6Header.Dst[12:16]
	v4Src := v6Header.Src[12:16]

	var hopLimit uint8 = 255
	if v6Header.HopLimit >= 0 && v6Header.HopLimit <= 255 {
		hopLimit = uint8(v6Header.HopLimit)
	}

	if v6Header.NextHeader < 0 || v6Header.NextHeader > 255 {
		logger.Warn("Invalid next header (protocol)", zap.Int("next_header", v6Header.NextHeader))
		return
	}

	v4Header := &layers.IPv4{
		BaseLayer: layers.BaseLayer{
			Contents: nil,
			Payload:  data,
		},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0, // Computed upon serialization
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        hopLimit,
		Protocol:   layers.IPProtocol(v6Header.NextHeader),
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
		hook(v4Header, data)
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
		zap.String("v6_src", v6Header.Src.String()),
		zap.String("v6_dst", v6Header.Dst.String()),
		zap.String("v4_src", v4Src.String()),
		zap.String("v4_dst", v4Dst.String()),
	)
}
