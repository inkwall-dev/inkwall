// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// The exporter POSTs from the operator's address, which can reach
// in-cluster Services and, on many clouds, the instance metadata service
// (design 0010 §7). Its dialer refuses the addresses a hostile endpoint
// would aim at, checked on the resolved address at connect time, so DNS
// rebinding can't get around it. Other private ranges stay allowed:
// in-cluster Collectors live there.

// AddressRefusedError is a connection refused by the dialer's guard. Its
// message names the address class, never the address.
type AddressRefusedError struct {
	// Class is loopback, unspecified, link-local or metadata.
	Class string
}

func (e *AddressRefusedError) Error() string {
	return "the sink's address is refused: " + e.Class
}

var (
	// AWS's IPv6 instance metadata service, outside fe80::/10.
	awsMetadataV6 = netip.MustParseAddr("fd00:ec2::254")
	// Alibaba Cloud's metadata service, outside 169.254.0.0/16.
	alibabaMetadata = netip.MustParseAddr("100.100.100.200")
	// The NAT64 well-known prefix (RFC 6052): its last 32 bits are an
	// IPv4 address.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
	// The local-use NAT64 prefix (RFC 8215).
	localNAT64 = netip.MustParsePrefix("64:ff9b:1::/48")
	// "This network": Linux connects 0.0.0.0 to the host itself.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
)

// refusedClass returns why the dialer refuses addr, or "" when it may
// connect. An IPv4-mapped IPv6 address, or one in the NAT64 prefix, is
// checked as the IPv4 address it carries.
func refusedClass(addr netip.Addr) string {
	addr = addr.WithZone("")
	if addr.Is6() && localNAT64.Contains(addr) {
		// RFC 8215's local-use prefix, which a network divides as it
		// likes: the IPv4 address may sit where any RFC 6052 prefix length
		// within it puts it. Refused if any of them is.
		b := addr.As16()
		for _, v4 := range [][4]byte{
			{b[6], b[7], b[9], b[10]},    // /48
			{b[7], b[9], b[10], b[11]},   // /56
			{b[9], b[10], b[11], b[12]},  // /64
			{b[12], b[13], b[14], b[15]}, // /96
		} {
			// Zeros elsewhere read as 0.x.x.x: not a target in any layout.
			if class := refusedClass(netip.AddrFrom4(v4)); class != "" && class != "unspecified" {
				return class
			}
		}
		return ""
	}
	if addr.Is6() && nat64.Contains(addr) {
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	addr = addr.Unmap()
	switch {
	case !addr.IsValid():
		return "unspecified"
	case addr.IsLoopback():
		return "loopback"
	case addr.IsUnspecified(), addr.Is4() && thisNetwork.Contains(addr):
		return "unspecified"
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return "link-local"
	case addr == awsMetadataV6, addr == alibabaMetadata:
		return "metadata"
	}
	return ""
}

// guardControl is a net.Dialer's Control: it runs for each address the
// dialer tries, after resolution.
func guardControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &AddressRefusedError{Class: "unspecified"}
	}
	class := refusedClass(ap.Addr())
	if class == "loopback" && testLoopback.Load() > 0 {
		class = ""
	}
	if class != "" {
		return &AddressRefusedError{Class: class}
	}
	return nil
}

// Tests let their sinks on the loopback through (testLoopback), and
// resolve names themselves (testResolver). Never set otherwise.
var (
	testLoopback atomic.Int32
	testResolver atomic.Pointer[net.Resolver]
)

// newDialer returns the guarded dialer every sink's transport uses.
func newDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: guardControl, Resolver: testResolver.Load()}
}

// dialContext dials address through the guard. A name that resolves only
// to refused addresses fails with an AddressRefusedError.
func dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := newDialer().DialContext(ctx, network, address)
	if err != nil {
		if refused, ok := errors.AsType[*AddressRefusedError](err); ok {
			// Keep the class only: the address stays out of status.
			return nil, fmt.Errorf("dial: %w", refused)
		}
		return nil, err
	}
	return conn, nil
}
