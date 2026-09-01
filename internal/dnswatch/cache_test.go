package dnswatch

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func response(t *testing.T, qname string, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(qname)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, ID: 7})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, a := range answers {
		var err error
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(a.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(a.Header, *body)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(a.Header, *body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func hdr(name string, typ dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: ttl}
}

func TestObserveThroughCNAME(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(0)
	msg := response(t, "Registry.NPMJS.org.",
		dnsmessage.Resource{Header: hdr("registry.npmjs.org.", dnsmessage.TypeCNAME, 300), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.cloudflare.net.")}},
		dnsmessage.Resource{Header: hdr("edge.cloudflare.net.", dnsmessage.TypeA, 60), Body: &dnsmessage.AResource{A: [4]byte{104, 16, 1, 1}}},
		dnsmessage.Resource{Header: hdr("edge.cloudflare.net.", dnsmessage.TypeAAAA, 60), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700::1").As16()}},
	)
	n, err := c.Observe(msg, now)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for _, ip := range []string{"104.16.1.1", "2606:4700::1", "::ffff:104.16.1.1"} {
		name, ok := c.Lookup(netip.MustParseAddr(ip), now)
		if !ok || name != "registry.npmjs.org" {
			t.Fatalf("%s -> %q %v; want the question name, not the cname target", ip, name, ok)
		}
	}
	if _, ok := c.Lookup(netip.MustParseAddr("104.16.1.1"), now.Add(61*time.Second)); ok {
		t.Fatal("should have expired at ttl")
	}
}

func TestMinTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(5 * time.Minute)
	msg := response(t, "a.example.", dnsmessage.Resource{Header: hdr("a.example.", dnsmessage.TypeA, 5), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}})
	if _, err := c.Observe(msg, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Lookup(netip.MustParseAddr("192.0.2.1"), now.Add(4*time.Minute)); !ok {
		t.Fatal("min ttl should keep it alive")
	}
	c.Purge(now.Add(6 * time.Minute))
	if c.Len() != 0 {
		t.Fatal("purge should have dropped it")
	}
}

func TestMostRecentNameWins(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(0)
	a := dnsmessage.Resource{Header: hdr("x.", dnsmessage.TypeA, 60), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}}}
	c.Observe(response(t, "first.example.", a), now)
	c.Observe(response(t, "second.example.", a), now.Add(time.Second))
	if name, _ := c.Lookup(netip.MustParseAddr("192.0.2.9"), now.Add(2*time.Second)); name != "second.example" {
		t.Fatalf("got %q", name)
	}
}

func TestQueryIgnored(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	msg, _ := b.Finish()
	if _, err := New(0).Observe(msg, time.Now()); !errors.Is(err, ErrNotResponse) {
		t.Fatalf("got %v", err)
	}
}

func TestGarbage(t *testing.T) {
	if _, err := New(0).Observe([]byte("not dns"), time.Now()); err == nil {
		t.Fatal("want error")
	}
}
