package procs

import (
	"net/netip"
	"testing"
)

func TestParseNetLine(t *testing.T) {
	cases := []struct {
		line  string
		ip    string
		port  uint16
		inode uint64
	}{
		{"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24680 1 0000000000000000 100 0 0 10 0", "127.0.0.1", 8080, 24680},
		{"   4: 0202000A:C3B2 22D8B8C0:01BB 01 00000000:00000000 02:000000E3 00000000  1000        0 999 2 0000000000000000 20 4 30 10 -1", "10.0.2.2", 50098, 999},
		{"   0: 0000000000000000FFFF00000100007F:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0", "127.0.0.1", 53, 31337},
		{"   2: 000080FE00000000FF3F2C4E2BD51E5A:D2C8 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4242 2 0000000000000000 0", "fe80::4e2c:3fff:5a1e:d52b", 53960, 4242},
	}
	for _, tc := range cases {
		e, ok := parseNetLine(tc.line)
		if !ok {
			t.Fatalf("unparsed: %s", tc.line)
		}
		if e.local != netip.MustParseAddr(tc.ip) || e.port != tc.port || e.inode != tc.inode {
			t.Fatalf("got %+v", e)
		}
	}
	if _, ok := parseNetLine("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"); ok {
		t.Fatal("header line parsed")
	}
}

func TestCgroupFromProc(t *testing.T) {
	if got := cgroupFromProc("0::/system.slice/app.service\n"); got != "system.slice/app.service" {
		t.Fatalf("%q", got)
	}
	if got := cgroupFromProc("0::/\n"); got != "" {
		t.Fatalf("root should be empty, got %q", got)
	}
	if got := cgroupFromProc("12:pids:/user.slice\n1:name=systemd:/user.slice\n"); got != "" {
		t.Fatalf("v1 only host: %q", got)
	}
}
