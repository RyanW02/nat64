package internal

import "net"

func IPv4ToNAT64(ip net.IP) net.IP {
	if ip.To4() == nil {
		return ip // IPv6 is already an IPv6 address
	}

	ip = ip.To4()

	natIp := make(net.IP, 16)
	natIp[0] = 0x00
	natIp[1] = 0x64
	natIp[2] = 0xff
	natIp[3] = 0x9b

	natIp[12] = ip[0]
	natIp[13] = ip[1]
	natIp[14] = ip[2]
	natIp[15] = ip[3]
	return natIp
}
