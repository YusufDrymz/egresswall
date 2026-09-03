package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// Webhook posts refusals to a URL as JSON. Events are coalesced over a
// window so a process retrying in a loop is one line with a count, not a
// request per packet.
type Webhook struct {
	URL    string
	Client *http.Client
	// Window is how long events pile up before a request goes out.
	Window time.Duration
	// Queue is how many events may wait; past that they are counted as
	// dropped and thrown away, because refusing to block is the point.
	Queue int
	// Now and Log exist for tests.
	Now func() time.Time
	Log io.Writer

	once    sync.Once
	events  chan Event
	done    chan struct{}
	dropped int64
	mu      sync.Mutex
}

// Payload is what lands at the other end.
type Payload struct {
	Source  string    `json:"source"`
	Host    string    `json:"host"`
	Sent    time.Time `json:"sent"`
	Dropped int64     `json:"dropped,omitempty"`
	Refused []Refusal `json:"refused"`
}

// Refusal is one coalesced destination in a payload.
type Refusal struct {
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	Count  int       `json:"count"`
	Rule   string    `json:"rule,omitempty"`
	Host   string    `json:"host,omitempty"`
	IP     string    `json:"ip"`
	Port   uint16    `json:"port"`
	Proto  string    `json:"proto,omitempty"`
	Cgroup string    `json:"cgroup,omitempty"`
}

const (
	defaultWindow = 5 * time.Second
	defaultQueue  = 2048
)

func NewWebhook(url string) *Webhook {
	w := &Webhook{URL: url}
	w.start()
	return w
}

func (w *Webhook) start() {
	w.once.Do(func() {
		if w.Window <= 0 {
			w.Window = defaultWindow
		}
		if w.Queue <= 0 {
			w.Queue = defaultQueue
		}
		if w.Client == nil {
			w.Client = &http.Client{Timeout: 10 * time.Second}
		}
		if w.Now == nil {
			w.Now = time.Now
		}
		if w.Log == nil {
			w.Log = os.Stderr
		}
		w.events = make(chan Event, w.Queue)
		w.done = make(chan struct{})
		go w.loop()
	})
}

// Send never blocks: a full queue means the host is refusing faster than the
// endpoint can take it, and the count of what was thrown away rides along
// with the next request.
func (w *Webhook) Send(e Event) {
	w.start()
	select {
	case w.events <- e:
	default:
		w.mu.Lock()
		w.dropped++
		w.mu.Unlock()
	}
}

// Close flushes what is pending and stops the loop.
func (w *Webhook) Close() error {
	w.start()
	close(w.events)
	<-w.done
	return nil
}

func (w *Webhook) loop() {
	defer close(w.done)
	batch := map[key]*Group{}
	timer := time.NewTimer(w.Window)
	defer timer.Stop()
	for {
		select {
		case e, ok := <-w.events:
			if !ok {
				w.post(batch)
				return
			}
			k := e.key()
			if g, seen := batch[k]; seen {
				g.Count++
				g.Last = e.At
			} else {
				batch[k] = &Group{Event: e, Count: 1, Last: e.At}
			}
		case <-timer.C:
			if len(batch) > 0 {
				w.post(batch)
				batch = map[key]*Group{}
			}
			timer.Reset(w.Window)
		}
	}
}

func (w *Webhook) post(batch map[key]*Group) {
	if len(batch) == 0 {
		return
	}
	host, _ := os.Hostname()
	w.mu.Lock()
	dropped := w.dropped
	w.dropped = 0
	w.mu.Unlock()

	p := Payload{Source: "egresswall", Host: host, Sent: w.Now(), Dropped: dropped}
	for _, g := range batch {
		p.Refused = append(p.Refused, Refusal{
			First: g.At, Last: g.Last, Count: g.Count,
			Rule: g.Rule, Host: g.Host, IP: g.IP.String(),
			Port: g.Port, Proto: g.Proto, Cgroup: g.Cgroup,
		})
	}
	sort.Slice(p.Refused, func(i, j int) bool {
		if p.Refused[i].Count != p.Refused[j].Count {
			return p.Refused[i].Count > p.Refused[j].Count
		}
		return p.Refused[i].IP < p.Refused[j].IP
	})
	body, err := json.Marshal(p)
	if err != nil {
		fmt.Fprintln(w.Log, "egresswall: alert encode:", err)
		return
	}
	// one retry: endpoints restart, and losing an alert to a deploy would be
	// a poor reason to miss an exfiltration attempt
	for attempt := 0; attempt < 2; attempt++ {
		if err = w.send(body); err == nil {
			return
		}
		if attempt == 0 {
			time.Sleep(time.Second)
		}
	}
	fmt.Fprintln(w.Log, "egresswall: alert webhook:", err)
}

func (w *Webhook) send(body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "egresswall")
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s said %s", w.URL, resp.Status)
	}
	return nil
}
