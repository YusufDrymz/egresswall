// Package packet pulls the few fields egresswall cares about out of a raw
// network-layer frame: addresses, ports, protocol, TCP SYN/ACK, payload.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ProtoTCP = 6
	ProtoUDP = 17
)

var ErrShort = errors.New("packet: truncated")

// ErrUnhandled covers everything that is not plain IPv4/IPv6 carrying TCP or
// UDP: ICMP, IPv6 extension headers, fragments. Learn mode just skips those.
var ErrUnhandled = errors.New("packet: not tcp/udp over ip")

type Packet struct {
	Src, Dst         netip.Addr
	Proto            uint8
	SrcPort, DstPort uint16
	SYN, ACK         bool
	Payload          []byte // transport payload; DNS lives here for UDP 53
}

func (p Packet) IsTCP() bool { return p.Proto == ProtoTCP }
func (p Packet) IsUDP() bool { return p.Proto == ProtoUDP }

// Parse takes a frame that starts at the IP header (what an AF_PACKET
// SOCK_DGRAM socket hands over).
func Parse(b []byte) (Packet, error) {
	if len(b) < 1 {
		return Packet{}, ErrShort
	}
	switch b[0] >> 4 {
	case 4:
		return parseV4(b)
	case 6:
		return parseV6(b)
	}
	return Packet{}, ErrUnhandled
}

func parseV4(b []byte) (Packet, error) {
	if len(b) < 20 {
		return Packet{}, ErrShort
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, ErrShort
	}
	// more-fragments or a fragment offset: transport header is elsewhere
	if flagsFrag := binary.BigEndian.Uint16(b[6:8]); flagsFrag&0x3fff != 0 {
		return Packet{}, ErrUnhandled
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl {
		return Packet{}, ErrShort
	}
	if total < len(b) {
		b = b[:total] // trailing padding on short frames
	}
	p := Packet{
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
		Proto: b[9],
	}
	return parseTransport(p, b[ihl:])
}

func parseV6(b []byte) (Packet, error) {
	if len(b) < 40 {
		return Packet{}, ErrShort
	}
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 40+plen {
		return Packet{}, ErrShort
	}
	p := Packet{
		Src:   netip.AddrFrom16([16]byte(b[8:24])),
		Dst:   netip.AddrFrom16([16]byte(b[24:40])),
		Proto: b[6],
	}
	return parseTransport(p, b[40:40+plen])
}

func parseTransport(p Packet, b []byte) (Packet, error) {
	switch p.Proto {
	case ProtoUDP:
		if len(b) < 8 {
			return Packet{}, ErrShort
		}
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
		p.Payload = b[8:]
		return p, nil
	case ProtoTCP:
		if len(b) < 20 {
			return Packet{}, ErrShort
		}
		off := int(b[12]>>4) * 4
		if off < 20 || len(b) < off {
			return Packet{}, ErrShort
		}
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
		p.SYN = b[13]&0x02 != 0
		p.ACK = b[13]&0x10 != 0
		p.Payload = b[off:]
		return p, nil
	}
	return Packet{}, ErrUnhandled
}
