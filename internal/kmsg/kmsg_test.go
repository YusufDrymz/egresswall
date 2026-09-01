package kmsg

import "testing"

func TestParseLine(t *testing.T) {
	cases := []struct {
		line string
		want Event
		ok   bool
	}{
		{
			"6,1024,7739412,-;egresswall default-deny: IN= OUT=eth0 SRC=172.17.0.2 DST=93.184.216.34 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=41234 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 ",
			Event{Dst: mustAddr("93.184.216.34"), Port: 443, Proto: "tcp"}, true,
		},
		{
			"4,1,2,-;egresswall deny[cloud-metadata]: IN= OUT=eth0 SRC=10.0.0.5 DST=169.254.169.254 PROTO=TCP SPT=1 DPT=80",
			Event{Rule: "cloud-metadata", Dst: mustAddr("169.254.169.254"), Port: 80, Proto: "tcp"}, true,
		},
		{
			"egresswall deny[x]: IN= OUT=eth0 SRC=fd00::1 DST=2606:4700::1 PROTO=UDP SPT=1 DPT=53",
			Event{Rule: "x", Dst: mustAddr("2606:4700::1"), Port: 53, Proto: "udp"}, true,
		},
		{"6,1,2,-;usb 1-1: new device", Event{}, false},
		{"6,1,2,-;egresswall deny[broken: DST=1.2.3.4", Event{}, false},
		{"6,1,2,-;egresswall default-deny: IN= OUT=eth0", Event{}, false},
	}
	for _, tc := range cases {
		got, ok := ParseLine(tc.line)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("%q: got %+v %v, want %+v %v", tc.line, got, ok, tc.want, tc.ok)
		}
	}
}
