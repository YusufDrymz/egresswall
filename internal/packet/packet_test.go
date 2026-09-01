package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func v4(src, dst string, proto byte, transport []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(transport)))
	h[8] = 64
	h[9] = proto
	copy(h[12:], netip.MustParseAddr(src).AsSlice())
	copy(h[16:], netip.MustParseAddr(dst).AsSlice())
	return append(h, transport...)
}

func v6(src, dst string, proto byte, transport []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(transport)))
	h[6] = proto
	h[7] = 64
	copy(h[8:], netip.MustParseAddr(src).AsSlice())
	copy(h[24:], netip.MustParseAddr(dst).AsSlice())
	return append(h, transport...)
}

func udp(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func tcp(sport, dport uint16, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = 5 << 4
	h[13] = flags
	return append(h, payload...)
}

func TestUDPv4(t *testing.T) {
	p, err := Parse(v4("10.0.0.2", "1.1.1.1", ProtoUDP, udp(40000, 53, []byte("dns"))))
	if err != nil {
		t.Fatal(err)
	}
	if p.Src.String() != "10.0.0.2" || p.Dst.String() != "1.1.1.1" || !p.IsUDP() ||
		p.SrcPort != 40000 || p.DstPort != 53 || string(p.Payload) != "dns" {
		t.Fatalf("%+v", p)
	}
}

func TestTCPSynV6(t *testing.T) {
	p, err := Parse(v6("2001:db8::1", "2606:4700::1", ProtoTCP, tcp(51000, 443, 0x02, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsTCP() || !p.SYN || p.ACK || p.DstPort != 443 || p.Dst.String() != "2606:4700::1" {
		t.Fatalf("%+v", p)
	}
}

func TestTCPSynAck(t *testing.T) {
	p, err := Parse(v4("1.2.3.4", "10.0.0.2", ProtoTCP, tcp(443, 51000, 0x12, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !p.SYN || !p.ACK {
		t.Fatalf("%+v", p)
	}
}

func TestTrailingPaddingTrimmed(t *testing.T) {
	frame := append(v4("10.0.0.2", "1.1.1.1", ProtoUDP, udp(1, 2, []byte("x"))), 0, 0, 0, 0)
	p, err := Parse(frame)
	if err != nil || string(p.Payload) != "x" {
		t.Fatalf("%v %q", err, p.Payload)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]struct {
		b    []byte
		want error
	}{
		"empty":            {nil, ErrShort},
		"icmp":             {v4("10.0.0.2", "1.1.1.1", 1, make([]byte, 8)), ErrUnhandled},
		"ipv4 header only": {v4("10.0.0.2", "1.1.1.1", ProtoTCP, nil), ErrShort},
		"ipv5":             {[]byte{0x50}, ErrUnhandled},
		"v6 hop-by-hop":    {v6("::1", "::2", 0, make([]byte, 8)), ErrUnhandled},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(tc.b); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestFragmentSkipped(t *testing.T) {
	b := v4("10.0.0.2", "1.1.1.1", ProtoUDP, udp(1, 2, nil))
	binary.BigEndian.PutUint16(b[6:], 0x2000) // more fragments
	if _, err := Parse(b); !errors.Is(err, ErrUnhandled) {
		t.Fatal(err)
	}
}
