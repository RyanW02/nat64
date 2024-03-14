package main

import (
	"fmt"
	"nat64/internal"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./convert-address <address>")
		os.Exit(1)
	}

	ip := net.ParseIP(os.Args[1])
	if ip == nil || ip.To4() == nil {
		fmt.Println("Invalid IPv4 address")
		os.Exit(1)
	}

	natIp := internal.IPv4ToNAT64(ip)
	fmt.Println(natIp.String())
}
