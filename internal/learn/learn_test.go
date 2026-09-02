package learn

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/YusufDrymz/egresswall/internal/dnswatch"
	"github.com/YusufDrymz/egresswall/internal/packet"
	"github.com/YusufDrymz/egresswall/internal/policy"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func tcpSyn(dst string, port uint16) packet.Packet {
	return packet.Packet{Src: addr("10.0.0.2"), Dst: addr(dst), Proto: packet.ProtoTCP, SrcPort: 50000, DstPort: port, SYN: true}
}

func udpOut(dst string, sport, dport uint16) packet.Packet {
	return packet.Packet{Src: addr("10.0.0.2"), Dst: addr(dst), Proto: packet.ProtoUDP, SrcPort: sport, DstPort: dport}
}

func dnsAnswer(t *testing.T, name string, ip string) packet.Packet {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: addr(ip).As4()})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return packet.Packet{Src: addr("1.1.1.1"), Dst: addr("10.0.0.2"), Proto: packet.ProtoUDP, SrcPort: 53, DstPort: 40000, Payload: msg}
}

func TestFlowAttribution(t *testing.T) {
	now := time.Unix(1000, 0)
	o := NewObserver(dnswatch.New(0))
	var news []string
	o.OnNew = func(e Entry) { news = append(news, e.Host) }

	o.Packet(dnsAnswer(t, "registry.npmjs.org", "104.16.1.1"), false, now)
	o.Packet(tcpSyn("104.16.1.1", 443), true, now.Add(time.Second))
	o.Packet(tcpSyn("104.16.1.1", 443), true, now.Add(2*time.Second))
	o.Packet(tcpSyn("203.0.113.5", 8443), true, now.Add(3*time.Second)) // no dns for this one

	got := o.Entries()
	if len(got) != 2 {
		t.Fatalf("entries: %+v", got)
	}
	if got[0].Host != "registry.npmjs.org" || !got[0].Domain || got[0].Hits != 2 || got[0].Port != 443 || got[0].Proto != "tcp" {
		t.Fatalf("%+v", got[0])
	}
	if len(got[0].IPs) != 1 || got[0].IPs[0] != addr("104.16.1.1") {
		t.Fatalf("ips %v", got[0].IPs)
	}
	if got[1].Host != "203.0.113.5" || got[1].Domain {
		t.Fatalf("%+v", got[1])
	}
	if strings.Join(news, ",") != "registry.npmjs.org,203.0.113.5" {
		t.Fatalf("OnNew fired for %v", news)
	}
}

func TestOnlySynStartsAFlow(t *testing.T) {
	o := NewObserver(dnswatch.New(0))
	now := time.Now()
	ack := tcpSyn("203.0.113.5", 443)
	ack.SYN, ack.ACK = false, true
	synack := tcpSyn("203.0.113.5", 443)
	synack.ACK = true
	o.Packet(ack, true, now)
	o.Packet(synack, true, now)
	if len(o.Entries()) != 0 {
		t.Fatal("ack and syn-ack are not new flows")
	}
}

func TestInboundAndLocalIgnored(t *testing.T) {
	o := NewObserver(dnswatch.New(0))
	now := time.Now()
	o.Packet(tcpSyn("203.0.113.5", 443), false, now) // somebody connecting to us
	o.Packet(tcpSyn("127.0.0.1", 5432), true, now)
	o.Packet(tcpSyn("::1", 5432), true, now)
	o.Packet(tcpSyn("224.0.0.251", 5353), true, now)
	if n := len(o.Entries()); n != 0 {
		t.Fatalf("got %d entries", n)
	}
}

func TestUDPReplySuppressed(t *testing.T) {
	o := NewObserver(dnswatch.New(0))
	now := time.Now()
	// someone queried our local dns/ntp-ish service on 5353 from 198.51.100.7:6000
	o.Packet(packet.Packet{Src: addr("198.51.100.7"), Dst: addr("10.0.0.2"), Proto: packet.ProtoUDP, SrcPort: 6000, DstPort: 5353}, false, now)
	o.Packet(udpOut("198.51.100.7", 5353, 6000), true, now.Add(time.Millisecond))
	if len(o.Entries()) != 0 {
		t.Fatal("our reply to an inbound udp packet is not an outbound flow")
	}
	// a genuine outbound udp to the same host on a different port still counts
	o.Packet(udpOut("198.51.100.7", 40000, 123), true, now.Add(time.Second))
	if e := o.Entries(); len(e) != 1 || e[0].Port != 123 || e[0].Proto != "udp" {
		t.Fatalf("%+v", e)
	}
	// and after the window the mirror tuple is a flow again
	o.Sweep(now.Add(2 * replyWindow))
	o.Packet(udpOut("198.51.100.7", 5353, 6000), true, now.Add(2*replyWindow))
	if len(o.Entries()) != 2 {
		t.Fatal("suppression should expire")
	}
}

func TestDNSQueryAfterResponseIsStillAFlow(t *testing.T) {
	o := NewObserver(dnswatch.New(0))
	now := time.Now()
	o.Packet(udpOut("1.1.1.1", 40000, 53), true, now)
	o.Packet(dnsAnswer(t, "a.example", "192.0.2.1"), false, now.Add(time.Millisecond))
	o.Packet(udpOut("1.1.1.1", 40000, 53), true, now.Add(time.Second)) // same socket, next query
	e := o.Entries()
	if len(e) != 1 || e[0].Hits != 2 {
		t.Fatalf("a response on a socket we opened must not turn our next query into a reply: %+v", e)
	}
}

func TestWritePolicyRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)
	o := NewObserver(dnswatch.New(0))
	o.Packet(udpOut("1.1.1.1", 40000, 53), true, now) // the query goes out first
	o.Packet(dnsAnswer(t, "registry.npmjs.org", "104.16.1.1"), false, now)
	o.Packet(dnsAnswer(t, "github.com", "140.82.121.4"), false, now)
	o.Packet(tcpSyn("104.16.1.1", 443), true, now)
	o.Packet(tcpSyn("140.82.121.4", 443), true, now)
	o.Packet(tcpSyn("140.82.121.4", 22), true, now)
	o.Packet(tcpSyn("169.254.169.254", 80), true, now)

	var buf bytes.Buffer
	if err := WritePolicy(&buf, o.Entries(), now.Add(-2*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`domains: ["github.com"]`,
		`ports: ["22", "443"]`,
		`domains: ["registry.npmjs.org"]`,
		`cidrs: ["1.1.1.1"]`,
		`proto: udp`,
		`seen 1 times during learn; denied anyway`,
		`no dns name seen`,
		`after 2h0m0s of traffic`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `cidrs: ["169.254.169.254"]
    ports`) {
		t.Fatalf("metadata must not become an allow rule:\n%s", out)
	}
	set, err := policy.Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if d := set.Evaluate(policy.Dest{Domain: "github.com", Port: 22}); d.Verdict != policy.Allow {
		t.Fatalf("%+v", d)
	}
	if d := set.Evaluate(policy.Dest{IP: addr("169.254.169.254"), Port: 80}); d.Verdict != policy.Deny || d.Rule != "cloud-metadata" {
		t.Fatalf("%+v", d)
	}
	if d := set.Evaluate(policy.Dest{Domain: "evil.example", Port: 443}); d.Verdict != policy.Deny {
		t.Fatalf("%+v", d)
	}
}

func TestOriginsInComment(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	o := NewObserver(dnswatch.New(0))
	o.Owner = func(_ netip.Addr, port uint16, _ string) string {
		switch port {
		case 50000:
			return "system.slice/app.service"
		case 50001:
			return "system.slice/cron.service"
		}
		return ""
	}
	o.Packet(dnsAnswer(t, "api.example", "192.0.2.10"), false, now)
	for i := 0; i < 3; i++ {
		o.Packet(tcpSyn("192.0.2.10", 443), true, now)
	}
	cron := tcpSyn("192.0.2.10", 443)
	cron.SrcPort = 50001
	o.Packet(cron, true, now)
	nobody := tcpSyn("192.0.2.10", 443)
	nobody.SrcPort = 60000
	o.Packet(nobody, true, now)

	e := o.Entries()
	if len(e) != 1 || e[0].Origins["system.slice/app.service"] != 3 || e[0].Origins[""] != 1 {
		t.Fatalf("%+v", e)
	}
	var buf bytes.Buffer
	if err := WritePolicy(&buf, e, now, now); err != nil {
		t.Fatal(err)
	}
	want := `from system.slice/app.service (3), system.slice/cron.service (1), unknown process (1)`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("missing %q in:\n%s", want, buf.String())
	}
}

func TestWritePolicyEmpty(t *testing.T) {
	var buf bytes.Buffer
	now := time.Now()
	if err := WritePolicy(&buf, nil, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Parse(buf.Bytes()); err != nil {
		t.Fatalf("empty learn must still produce a loadable file: %v\n%s", err, buf.String())
	}
}
