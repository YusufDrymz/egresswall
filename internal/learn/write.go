package learn

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YusufDrymz/egresswall/internal/policy"
)

var metadataIP = netip.MustParseAddr("169.254.169.254")

// WritePolicy renders the observed destinations as a policy file, one rule
// per host with the ports merged. The output is parsed back through the
// policy package before anything is written, so what lands on disk always
// loads.
func WritePolicy(w io.Writer, entries []Entry, started, now time.Time) error {
	type rule struct {
		host   string
		domain bool
		ports  []uint16
		protos map[string]bool
		first  time.Time
		last   time.Time
		hits   int
		from   map[string]int
	}
	var rules []*rule
	byHost := map[string]*rule{}
	var metadataHits int
	for _, e := range entries {
		if !e.Domain && e.Host == metadataIP.String() {
			metadataHits += e.Hits
			continue
		}
		r, ok := byHost[e.Host]
		if !ok {
			r = &rule{host: e.Host, domain: e.Domain, protos: map[string]bool{}, first: e.First, from: map[string]int{}}
			byHost[e.Host] = r
			rules = append(rules, r)
		}
		r.ports = append(r.ports, e.Port)
		r.protos[e.Proto] = true
		r.hits += e.Hits
		for cg, n := range e.Origins {
			r.from[cg] += n
		}
		if e.First.Before(r.first) {
			r.first = e.First
		}
		if e.Last.After(r.last) {
			r.last = e.Last
		}
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "# written by egresswall learn on %s after %s of traffic\n",
		now.UTC().Format("2006-01-02 15:04 UTC"), now.Sub(started).Round(time.Second))
	b.WriteString("# every rule below is something this host actually did; review, then enforce\n")
	b.WriteString("version: 1\ndefault: deny\n\n")
	b.WriteString("deny:\n  - name: cloud-metadata\n")
	if metadataHits > 0 {
		fmt.Fprintf(&b, "    comment: \"seen %d times during learn; denied anyway, drop this rule only if the host truly needs IMDS\"\n", metadataHits)
	} else {
		b.WriteString("    comment: \"never seen during learn, which is how it should stay\"\n")
	}
	b.WriteString("    cidrs: [\"169.254.169.254\"]\n\n")

	b.WriteString("allow:\n")
	if len(rules) == 0 {
		b.WriteString("  []\n")
	}
	for _, r := range rules {
		fmt.Fprintf(&b, "  - name: %s\n", yamlString(r.host))
		if r.domain {
			fmt.Fprintf(&b, "    domains: [%s]\n", yamlString(r.host))
		} else {
			fmt.Fprintf(&b, "    cidrs: [%s]\n", yamlString(r.host))
		}
		fmt.Fprintf(&b, "    ports: [%s]\n", portList(r.ports))
		if len(r.protos) == 1 {
			for p := range r.protos {
				fmt.Fprintf(&b, "    proto: %s\n", p)
			}
		}
		comment := fmt.Sprintf("first %s, last %s, %d hits",
			r.first.UTC().Format("01-02 15:04"), r.last.UTC().Format("01-02 15:04"), r.hits)
		if !r.domain {
			comment = "no dns name seen for this address; " + comment
		}
		if from := originsText(r.from); from != "" {
			comment += "; from " + from
		}
		fmt.Fprintf(&b, "    comment: %s\n", yamlString(comment))
	}

	if _, err := policy.Parse(b.Bytes()); err != nil {
		return fmt.Errorf("learn: rendered policy does not load, this is a bug: %w", err)
	}
	_, err := w.Write(b.Bytes())
	return err
}

// originsText lists the cgroups a host was reached from, busiest first, so
// the reader can decide whether the rule deserves a cgroup: line.
func originsText(from map[string]int) string {
	if len(from) == 0 {
		return ""
	}
	type kv struct {
		cg string
		n  int
	}
	var list []kv
	for cg, n := range from {
		list = append(list, kv{cg, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		if (list[i].cg == "") != (list[j].cg == "") {
			return list[j].cg == "" // the unknown bucket goes last
		}
		return list[i].cg < list[j].cg
	})
	var parts []string
	for _, e := range list {
		name := e.cg
		if name == "" {
			name = "unknown process"
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", name, e.n))
	}
	return strings.Join(parts, ", ")
}

func portList(ports []uint16) string {
	seen := map[uint16]bool{}
	var out []string
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, strconv.Quote(strconv.Itoa(int(p))))
		}
	}
	return strings.Join(out, ", ")
}

func yamlString(s string) string { return strconv.Quote(s) }
