package nat64

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"nat64/internal"
	"net"
)

type InboundHook func(header *layers.IPv6, data []byte)

func (g *Gateway) handleInboundPacket(bytes []byte) {
	logger := g.logger.With(zap.String("flow", "inbound"))

	if len(bytes) < ipv4.HeaderLen {
		logger.Warn("Packet too short to contain header", zap.Any("bytes", bytes))
		return
	}

	v4Header, err := ipv4.ParseHeader(bytes)
	if err != nil {
		logger.Error("Error parsing IPv4 header", zap.Error(err), zap.Any("bytes", bytes))
		return
	}

	data := bytes[ipv4.HeaderLen:]

	v6Src := internal.IPv4ToNAT64(v4Header.Src)

	v6Dst := make(net.IP, 16)
	copy(v6Dst, g.options.NAT6Prefix.IP)

	v4Dst := v4Header.Dst.To4()
	v6Dst[12] = v4Dst[0]
	v6Dst[13] = v4Dst[1]
	v6Dst[14] = v4Dst[2]
	v6Dst[15] = v4Dst[3]

	var hopLimit uint8 = 255
	if v4Header.TTL >= 0 && v4Header.TTL <= 255 {
		hopLimit = uint8(v4Header.TTL)
	}

	if v4Header.Protocol < 0 || v4Header.Protocol > 255 {
		logger.Warn("Invalid protocol", zap.Int("protocol", v4Header.Protocol))
		return
	}

	v6Header := &layers.IPv6{
		BaseLayer: layers.BaseLayer{
			Contents: nil,
			Payload:  data,
		},
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       0,
		NextHeader:   layers.IPProtocol(v4Header.Protocol),
		HopLimit:     hopLimit,
		SrcIP:        v6Src,
		DstIP:        v6Dst,
		HopByHop:     nil,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
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
