# nat64

## Introduction

This repository contains a provider-side [NAT64](https://en.wikipedia.org/wiki/NAT64) translator and
[DNS64](https://en.wikipedia.org/wiki/IPv6_transition_mechanism#DNS64) server, written in Go.

### NAT64 PLAT

The NAT64 PLAT runs in userspace and translates IPv6 packets into IPv4 packets and vice versa through a TUN device. It
has been tested with TCP, UDP, and ICMP traffic. The PLAT makes use of `iptables` / netfilter to perform the NAT
masquerading to share 1 IPv4 address, rather than pure SIIT alone. The `nat64` server will automatically configure the
required `iptables` / `ip6tables` rules and `ip` routes required, if the `-auto-configure` flag is set to `true`
(default).

Flags:

```
$ ./nat64 -h
Usage of ./nat64:
  -auto-configure
        Whether to automatically configure the IP routes and iptables NAT rules (default true)
  -buffer int
        Size of the buffer for reading packets - should be the same as the MTU of the TUN device (default 1500)
  -nat4-address string
        The RFC1918 IPv4 address to rewrite the NAT4 traffic to. This address will be masqueraded away by iptables. (default "10.10.10.10")
  -nat6-prefix string
        The IPv6 prefix to use internally for the NAT6 translation (default "::ffff:0:0:0/96")
  -tun string
        Name of the TUN device (default "tun0")
  -wan string
        Name of the WAN interface (default "eth0")
```

### DNS64

The DNS64 server can optionally be run alongside the NAT64 PLAT to provide DNS64 translation. The DNS64 server will
listen for DNS requests and proxy them to a recursive DNS resolver. If a request for an AAAA record is received, and the
recursive resolved does not return any results, the DNS64 server will perform an A record lookup and transform the
response into an AAAA record in the well-known `64:ff9b::/96` prefix.

Flags:

```
$ ./dns64 -h
Usage of ./dns64:
  -bind string
        Address to bind to (default ":53")
  -resolver string
        Recursive DNS resolver address (default "1.1.1.1:53")
  -tcp
        Use TCP (default true)
```

DNS lookup example:
```
root@v6:~# nslookup
> ipv4.google.com
Server:         fd00::1
Address:        fd00::1#53

Non-authoritative answer:
ipv4.google.com canonical name = ipv4.l.google.com.
Name:   ipv4.l.google.com
Address: 142.251.41.14
Name:   ipv4.l.google.com
Address: 64:ff9b::8efb:286e
```

## Building

To build the NAT64 and DNS64 binaries, simply run `make` in the current directory.

### Further Reading

- [RFC6146](https://tools.ietf.org/html/rfc6146) - Stateful NAT64: Network Address and Protocol Translation from IPv6
  Clients to IPv4 Servers
