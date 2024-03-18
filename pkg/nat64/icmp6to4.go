package nat64

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

func (g *Gateway) ICMPv6Converter(header *layers.IPv4, data []byte) ([]byte, bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeICMPv6, gopacket.Default)

	layer := packet.Layer(layers.LayerTypeICMPv6)
	if layer == nil {
		g.logger.Warn("Packet does not contain an ICMPv6 layer")
		return nil, true
	}

	icmp := layer.(*layers.ICMPv6)

	translatedType, translatedCode, forward := translateICMPv6(icmp.TypeCode.Type(), icmp.TypeCode.Code())
	if !forward {
		return nil, false
	}

	var id, seq uint16
	payloadBody := data
	if echo := packet.Layer(layers.LayerTypeICMPv6Echo); echo != nil {
		echoData := echo.(*layers.ICMPv6Echo)
		id = echoData.Identifier
		seq = echoData.SeqNumber

		if len(data) >= 8 {
			payloadBody = data[8:]
		} else {
			g.logger.Warn("Invalid ICMPv6 echo packet")
			return nil, false
		}
	}

	v4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(translatedType, translatedCode),
		Checksum: 0, // Computed upon serialization
		Id:       id,
		Seq:      seq,
	}

	// Serialize the ICMPv4 packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, v4, gopacket.Payload(payloadBody)); err != nil {
		g.logger.Error("Error serializing ICMPv4 packet", zap.Error(err))
		return nil, true // Forward without translation
	}

	header.Protocol = layers.IPProtocolICMPv4

	header.Payload = buf.Bytes()

	return buf.Bytes(), true
}

// translateICMPv6 translates an ICMPv6 message to an ICMPv4 message.
// The implementation is based on [RFC6145 Section 5](https://datatracker.ietf.org/doc/html/rfc6145#section-5).
func translateICMPv6(messageType, code uint8) (uint8, uint8, bool) {
	switch messageType {
	case layers.ICMPv6TypeDestinationUnreachable:
		switch code {
		case layers.ICMPv6CodeNoRouteToDst:
			return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHost, true
		case layers.ICMPv6CodeAdminProhibited:
			return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHostAdminProhibited, true
		case layers.ICMPv6CodeBeyondScopeOfSrc:
			return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHost, true
		case layers.ICMPv6CodeAddressUnreachable:
			return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHost, true
		case layers.ICMPv6CodePortUnreachable:
			return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort, true
		default:
			return 0, 0, false
		}
	case layers.ICMPv6TypePacketTooBig:
		return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded, true
	case layers.ICMPv6TypeTimeExceeded:
		return layers.ICMPv4TypeTimeExceeded, code, true
	case layers.ICMPv6TypeParameterProblem:
		switch code {
		case layers.ICMPv6CodeErroneousHeaderField:
			return layers.ICMPv4TypeParameterProblem, layers.ICMPv4CodePointerIndicatesError, true
		case layers.ICMPv6CodeUnrecognizedNextHeader:
			return layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeProtocol, true
		default:
			return 0, 0, false
		}
	case layers.ICMPv6TypeEchoRequest:
		return layers.ICMPv4TypeEchoRequest, 0, true
	case layers.ICMPv6TypeEchoReply:
		return layers.ICMPv4TypeEchoReply, 0, true
	default:
		return 0, 0, false
	}
}
