package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu       sync.Mutex
	payloads []Payload
	fail     int // fail this many requests before succeeding
	requests int
	got      chan struct{}
}

func (c *capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var p Payload
	json.NewDecoder(r.Body).Decode(&p)
	c.mu.Lock()
	c.requests++
	shouldFail := c.fail > 0
	if shouldFail {
		c.fail--
	} else {
		c.payloads = append(c.payloads, p)
	}
	c.mu.Unlock()
	if shouldFail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	select {
	case c.got <- struct{}{}:
	default:
	}
}

func (c *capture) wait(t *testing.T) Payload {
	t.Helper()
	select {
	case <-c.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no request arrived")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payloads[len(c.payloads)-1]
}

func event(ip string, port uint16, rule string) Event {
	return Event{
		At: time.Unix(1000, 0), Rule: rule, IP: netip.MustParseAddr(ip),
		Port: port, Proto: "tcp",
	}
}

func TestCoalesceAndPost(t *testing.T) {
	c := &capture{got: make(chan struct{}, 4)}
	srv := httptest.NewServer(c)
	defer srv.Close()

	w := &Webhook{URL: srv.URL, Window: 50 * time.Millisecond}
	defer w.Close()

	for i := 0; i < 5; i++ {
		e := event("1.2.3.4", 443, "")
		e.Host = "evil.example"
		e.At = time.Unix(int64(1000+i), 0)
		w.Send(e)
	}
	w.Send(event("5.6.7.8", 80, "cloud-metadata"))

	p := c.wait(t)
	if p.Source != "egresswall" || len(p.Refused) != 2 {
		t.Fatalf("%+v", p)
	}
	first := p.Refused[0]
	if first.Count != 5 || first.IP != "1.2.3.4" || first.Host != "evil.example" {
		t.Fatalf("busiest destination first, coalesced: %+v", first)
	}
	if !first.Last.Equal(time.Unix(1004, 0)) || !first.First.Equal(time.Unix(1000, 0)) {
		t.Fatalf("first and last: %+v", first)
	}
	if p.Refused[1].Rule != "cloud-metadata" || p.Refused[1].Count != 1 {
		t.Fatalf("%+v", p.Refused[1])
	}
}

func TestDifferentCgroupsStaySeparate(t *testing.T) {
	c := &capture{got: make(chan struct{}, 4)}
	srv := httptest.NewServer(c)
	defer srv.Close()
	w := &Webhook{URL: srv.URL, Window: 50 * time.Millisecond}
	defer w.Close()

	a := event("1.2.3.4", 443, "")
	a.Cgroup = "system.slice/app.service"
	b := event("1.2.3.4", 443, "")
	b.Cgroup = "system.slice/cron.service"
	w.Send(a)
	w.Send(b)

	if p := c.wait(t); len(p.Refused) != 2 {
		t.Fatalf("the same destination from two services is two findings: %+v", p.Refused)
	}
}

func TestFullQueueIsReportedNotBlocked(t *testing.T) {
	c := &capture{got: make(chan struct{}, 4)}
	srv := httptest.NewServer(c)
	defer srv.Close()
	// a queue of one and a long window: everything after the first is dropped
	w := &Webhook{URL: srv.URL, Window: 40 * time.Millisecond, Queue: 1}
	defer w.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			w.Send(event("1.2.3.4", 443, ""))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Send blocked")
	}
	p := c.wait(t)
	if p.Dropped == 0 {
		t.Fatal("dropped events must be counted in the payload")
	}
}

func TestRetryOnce(t *testing.T) {
	c := &capture{got: make(chan struct{}, 4), fail: 1}
	srv := httptest.NewServer(c)
	defer srv.Close()
	w := &Webhook{URL: srv.URL, Window: 30 * time.Millisecond}
	defer w.Close()

	w.Send(event("1.2.3.4", 443, ""))
	p := c.wait(t)
	if len(p.Refused) != 1 {
		t.Fatalf("%+v", p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requests != 2 {
		t.Fatalf("want one failure then one success, got %d requests", c.requests)
	}
}

func TestCloseFlushes(t *testing.T) {
	c := &capture{got: make(chan struct{}, 4)}
	srv := httptest.NewServer(c)
	defer srv.Close()
	w := &Webhook{URL: srv.URL, Window: time.Hour} // never fires on its own
	w.Send(event("9.9.9.9", 53, "dns"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.payloads) != 1 || c.payloads[0].Refused[0].IP != "9.9.9.9" {
		t.Fatalf("Close must flush what is pending: %+v", c.payloads)
	}
}

func TestNoRequestWhenNothingHappens(t *testing.T) {
	c := &capture{got: make(chan struct{}, 4)}
	srv := httptest.NewServer(c)
	defer srv.Close()
	w := &Webhook{URL: srv.URL, Window: 20 * time.Millisecond}
	time.Sleep(100 * time.Millisecond)
	w.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requests != 0 {
		t.Fatalf("a quiet host must not post anything, got %d requests", c.requests)
	}
}
