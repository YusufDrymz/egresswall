package main

import "testing"

func TestParseDest(t *testing.T) {
	cases := []struct {
		in, ip, proto string
		wantDomain    string
		wantIP        string
		wantPort      uint16
		wantErr       bool
	}{
		{in: "registry.npmjs.org:443", proto: "tcp", wantDomain: "registry.npmjs.org", wantPort: 443},
		{in: "10.0.0.5:5432", proto: "tcp", wantIP: "10.0.0.5", wantPort: 5432},
		{in: "[2606:4700::1]:443", proto: "tcp", wantIP: "2606:4700::1", wantPort: 443},
		{in: "github.com:22", ip: "140.82.121.4", proto: "tcp", wantDomain: "github.com", wantIP: "140.82.121.4", wantPort: 22},
		{in: "github.com", wantErr: true},
		{in: "github.com:0", wantErr: true},
		{in: "github.com:99999", wantErr: true},
		{in: "github.com:443", ip: "not-an-ip", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			d, err := parseDest(tc.in, tc.ip, tc.proto)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", d)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gotIP := ""
			if d.IP.IsValid() {
				gotIP = d.IP.String()
			}
			if d.Domain != tc.wantDomain || gotIP != tc.wantIP || d.Port != tc.wantPort || d.Proto != tc.proto {
				t.Fatalf("got %+v", d)
			}
		})
	}
}
