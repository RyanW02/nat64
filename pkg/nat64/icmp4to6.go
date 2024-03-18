package nat64

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"nat64/internal"
	"net"
)

func (g *Gateway) ICMPv4Converter(header *layers.IPv6, data []byte) ([]byte, bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeICMPv4, gopacket.Default)

	layer := packet.Layer(layers.LayerTypeICMPv4)
	if layer == nil {
		g.logger.Warn("Packet does not contain an ICMPv4 layer")
		return nil, true
	}

	icmp := layer.(*layers.ICMPv4)

	translatedType, translatedCode, forward := translateICMPv4(icmp.TypeCode.Type(), icmp.TypeCode.Code())
	if !forward {
		return nil, false
	}

	icmpV6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(translatedType, translatedCode),
		Checksum: 0, // Computed upon serialization
	}

	header.NextHeader = layers.IPProtocolICMPv6
	if err := icmpV6.SetNetworkLayerForChecksum(header); err != nil {
		g.logger.Error("Error setting network layer for ICMPv6 checksum", zap.Error(err))
		return nil, true
	}

	outboundLayers := []gopacket.SerializableLayer{icmpV6}
	if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest || icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
		outboundLayers = append(outboundLayers,
			&layers.ICMPv6Echo{
				Identifier: icmp.Id,
				SeqNumber:  icmp.Seq,
			},
			gopacket.Payload(data[8:]),
		)
	} else if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded || icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable {
		inner, err := convertICMPInner(g.options, data[8:])
		if err != nil {
			g.logger.Error("Error parsing ICMPv4 inner payload", zap.Error(err))
			return nil, true
		}

		outboundLayers = append(outboundLayers, gopacket.Payload{0, 0, 0, 0}, gopacket.Payload(inner))
	}

	// Serialize the ICMPv6 packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, outboundLayers...); err != nil {
		g.logger.Error("Error serializing ICMPv6 packet", zap.Error(err))
		return nil, true // Forward without translation
	}

	return buf.Bytes(), true
}

// translateICMPv4 translates an ICMPv4 message to an ICMPv6 message.
// The implementation is based on [RFC6145 Section 5](https://datatracker.ietf.org/doc/html/rfc6145#section-5).
func translateICMPv4(messageType, code uint8) (uint8, uint8, bool) {
	switch messageType {
	case layers.ICMPv4TypeEchoRequest:
		return layers.ICMPv6TypeEchoRequest, 0, true
	case layers.ICMPv4TypeEchoReply:
		return layers.ICMPv6TypeEchoReply, 0, true
	case layers.ICMPv4TypeDestinationUnreachable:
		switch code {
		case layers.ICMPv4CodeNet, layers.ICMPv4CodeHost:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeNoRouteToDst, true
		case layers.ICMPv4CodeProtocol:
			return layers.ICMPv6TypeParameterProblem, layers.ICMPv6CodeUnrecognizedNextHeader, true
		case layers.ICMPv4CodePort:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable, true
		case layers.ICMPv4CodeFragmentationNeeded:
			return layers.ICMPv6TypePacketTooBig, 0, true
		case layers.ICMPv4CodeSourceRoutingFailed:
			return layers.ICMPv6TypeDestinationUnreachable, 0, true
		case layers.ICMPv4CodeNetUnknown, layers.ICMPv4CodeHostUnknown, layers.ICMPv4CodeSourceIsolated:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeNoRouteToDst, true
		case layers.ICMPv4CodeNetAdminProhibited, layers.ICMPv4CodeHostAdminProhibited:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeAdminProhibited, true
		case layers.ICMPv4CodeNetTOS, layers.ICMPv4CodeHostTOS:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeNoRouteToDst, true
		case layers.ICMPv4CodeCommAdminProhibited:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeAdminProhibited, true
		case layers.ICMPv4CodeHostPrecedence:
			return 0, 0, false
		case layers.ICMPv4CodePrecedenceCutoff:
			return layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv4CodeHostAdminProhibited, true
		default:
			return 0, 0, false
		}
	case layers.ICMPv4TypeTimeExceeded:
		return layers.ICMPv6TypeTimeExceeded, code, true
	case layers.ICMPv4TypeParameterProblem:
		switch code {
		case layers.ICMPv4CodePointerIndicatesError:
			return layers.ICMPv6TypeParameterProblem, layers.ICMPv6CodeErroneousHeaderField, true
		case layers.ICMPv4CodeMissingOption:
			return 0, 0, false
		case layers.ICMPv4CodeBadLength:
			return layers.ICMPv6TypeParameterProblem, layers.ICMPv6CodeErroneousHeaderField, true
		default:
			return 0, 0, false
		}
	default:
		return 0, 0, false
	}
}

func convertICMPInner(options Options, data []byte) ([]byte, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if packet == nil {
		return nil, fmt.Errorf("failed to parse packet")
	}

	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return nil, fmt.Errorf("packet does not contain an IPv4 layer")
	}

	v4 := layer.(*layers.IPv4)

	// UDP header len + 32
	innerLen := min(40, len(data[ipv4.HeaderLen:]))

	// Netfilter conntrack uses the inner IPv6 header to match connections:
	// https://github.com/torvalds/linux/blob/741e9d668aa50c91e4f681511ce0e408d55dd7ce/net/netfilter/nf_conntrack_proto_icmp.c#L106
	// Therefore, we need to convert the inner source address to the IPv6 NAT address
	v6Src := make(net.IP, 16)
	copy(v6Src, options.NAT6Prefix.IP)
	copy(v6Src[12:], options.NAT4Address.To4())

	v6 := &layers.IPv6{
		Version:      6,
		TrafficClass: v4.TOS,
		FlowLabel:    0,
		Length:       uint16(ipv6.HeaderLen + innerLen),
		NextHeader:   v4.Protocol,
		HopLimit:     v4.TTL,
		SrcIP:        v6Src,
		DstIP:        internal.IPv4ToNAT64(v4.DstIP),
		HopByHop:     nil,
	}

	if v4.Protocol == layers.IPProtocolICMPv4 {
		v6.NextHeader = layers.IPProtocolICMPv6
	}

	outLayers := []gopacket.SerializableLayer{v6}
	if v4.NextLayerType() == layers.LayerTypeICMPv4 {
		icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

		translatedType, translatedCode, _ := translateICMPv4(icmp.TypeCode.Type(), icmp.TypeCode.Code())
		icmpV6 := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(translatedType, translatedCode),
			Checksum: 0, // Computed upon serialization
		}

		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest || icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
			outLayers = append(outLayers,
				icmpV6,
				&layers.ICMPv6Echo{
					Identifier: icmp.Id,
					SeqNumber:  icmp.Seq,
				},
				gopacket.Payload(data[8:]),
			)
		} else {
			outLayers = append(outLayers, icmpV6, gopacket.Payload{0, 0, 0, 0})
		}

		if err := icmpV6.SetNetworkLayerForChecksum(v6); err != nil {
			return nil, fmt.Errorf("error setting network layer for ICMPv6 checksum: %w", err)
		}
	} else {
		payload := data[ipv4.HeaderLen : ipv4.HeaderLen+innerLen]
		payload[4] = 0
		payload[5] = byte(innerLen)
		outLayers = append(outLayers, gopacket.Payload(payload))
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, outLayers...); err != nil {
		return nil, fmt.Errorf("error serializing IPv6 packet: %w", err)
	}

	return buf.Bytes(), nil
}
