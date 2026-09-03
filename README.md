# egresswall

[Türkçe](README.tr.md) · **English**

A server talks to a handful of places: its package registries, its database, its
API providers. A compromised dependency talks to one more. `egresswall` is a
learn-then-enforce egress firewall for plain Linux hosts: run it in `learn` mode
for a day and it writes down where the box actually connects, as domains and
ports rather than IPs. Switch to `enforce` and anything not on that list is
dropped and logged, including the first outbound call of a stolen token.

[![CI](https://github.com/YusufDrymz/egresswall/actions/workflows/ci.yml/badge.svg)](https://github.com/YusufDrymz/egresswall/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Status: early.** `learn`, `check` and `enforce` all work, including rules
> scoped to a service's cgroup, and are exercised end to end in CI on a real
> Linux runner. Nothing here is running in production yet.

## Why

The 2025 npm worm wave, and every supply-chain incident before it, followed the
same script: a build or app process pulls a poisoned package, the package reads
whatever credentials it can find, and it POSTs them somewhere. Every one of those
steps is hard to prevent. The last one is easy to notice, if the host has a list
of where it is supposed to talk and refuses the rest.

Kubernetes clusters get this from Cilium or Calico. GitHub Actions gets it from
Harden-Runner. Desktops get it from OpenSnitch or Little Snitch. A VPS, a Docker
host or a bare-metal box running your app gets `ufw`, which is inbound-minded, or
hand-written nftables rules nobody wants to maintain by hand. That gap is the
whole project.

## How it works

```
$ sudo egresswall learn -out egresswall.yaml       # watch for a day
$ egresswall check registry.npmjs.org:443          # ask the policy, offline
$ sudo egresswall enforce -policy egresswall.yaml  # refuse the rest, log it
```

Eight seconds of `learn` on a box that fetched two pages:

```
$ sudo egresswall learn -duration 8s -out learned.yaml
egresswall: learning, writing to learned.yaml on stop
new  192.168.65.7:53 udp
new  example.com:443 tcp
new  neverssl.com:80 tcp
egresswall: 3 destinations after 8s, policy written to learned.yaml
```

```yaml
# written by egresswall learn on 2026-09-01 19:49 UTC after 8s of traffic
# every rule below is something this host actually did; review, then enforce
version: 1
default: deny

deny:
  - name: cloud-metadata
    comment: "never seen during learn, which is how it should stay"
    cidrs: ["169.254.169.254"]

allow:
  - name: "example.com"
    domains: ["example.com"]
    ports: ["443"]
    proto: tcp
    comment: "first 09-01 19:49, last 09-01 19:49, 1 hits"
  - name: "neverssl.com"
    domains: ["neverssl.com"]
    ports: ["80"]
    proto: tcp
    comment: "first 09-01 19:49, last 09-01 19:49, 5 hits"
  - name: "192.168.65.7"
    cidrs: ["192.168.65.7"]
    ports: ["53"]
    proto: udp
    comment: "no dns name seen for this address; first 09-01 19:49, last 09-01 19:49, 6 hits"
```

`learn` opens one raw socket (AF_PACKET, cooked mode) on every interface and
reads two things off it: DNS answers, which build an address-to-name map, and
the first packet of every outbound flow, which the kernel marks as outgoing so
there is no guessing from addresses. TCP flows are counted at the SYN; for UDP,
whoever sent the first packet of a tuple is the initiator, so our replies to
inbound traffic do not show up as destinations. No conntrack, no nftables, no
kernel module: if the box can run a Go binary as root it can learn.

- **Domains, not IPs.** The policy says `*.pypi.org`; the daemon watches DNS
  answers on the host and keeps an nftables set of the IPs those names resolve
  to, expiring them on TTL. A connection to an IP that no allowed name resolved
  to is refused, which is the case for almost every exfiltration endpoint.
- **Deny wins, then allow in file order, then default.** Metadata service on
  `169.254.169.254` stays denied even when a broad rule allows port 443.
- **One binary, no agent, no cloud.** Policy is a YAML file you commit next to
  your deployment. Refusals go to the log with the name, the IP, the port and the
  rule, or the absence of one.

### enforce

```
$ sudo egresswall enforce -policy policy.yaml -verbose
egresswall: enforcing policy.yaml (5 rules, 2 address sets)
allow  104.20.23.154 (example.com):443 tcp  domain example.com
refused  93.184.216.34 (neverssl.com):80 tcp  default deny
refused  1.1.1.1:443 tcp  default deny
^C
egresswall: table removed, host is unfiltered again
```

`enforce` loads one nftables table, `inet egresswall`, with an output chain
and one timeout set per domain rule and address family. It keeps the same raw
socket open as `learn`: every DNS answer for a name a rule covers puts the
answered addresses into that rule's sets for the TTL (five minutes at least,
because applications cache longer than resolvers say). At startup the exact
names in the policy are resolved once so processes holding a cached address
are not refused until they resolve again; wildcards cannot be seeded.

Refused packets are rejected with an ICMP "administratively prohibited", not
silently dropped, so the process fails in milliseconds with a clear error
instead of hanging on a timeout. Each refusal is logged by the kernel with the
rule that caused it, and the daemon reads those back from `/dev/kmsg` and prints
them with the DNS name attached.

### Getting told about it

`-alert-webhook https://…` posts refusals as JSON. Events are coalesced over a
few seconds, so a process retrying in a loop is one entry with a count rather
than a request per packet:

```json
{
  "source": "egresswall",
  "host": "web-01",
  "sent": "2026-09-03T17:36:26Z",
  "refused": [
    {
      "first": "2026-09-03T17:36:23Z",
      "last": "2026-09-03T17:36:25Z",
      "count": 14,
      "host": "collect.evil.example",
      "ip": "203.0.113.9",
      "port": 443,
      "proto": "tcp",
      "cgroup": "system.slice/app.service"
    }
  ]
}
```

Posting never blocks the enforcing loop. If the endpoint is down the request is
retried once; if refusals arrive faster than it can take them they are counted
and the count rides along in the next payload as `dropped`. A quiet host posts
nothing.

Things worth knowing before running it on a box you care about:

- `-dry-run` touches nothing and prints what the policy would have refused.
  Run it first.
- `-print` shows the exact nft ruleset the policy becomes. Read it.
- Stopping the daemon cleanly removes the table: a firewall nobody is feeding
  DNS answers to would refuse everything within minutes. If the daemon crashes,
  the table stays and keeps refusing; `enforce -off` removes it.
- Inbound is untouched. SSH sessions survive; established connections are
  accepted without further checks.
- cgroup rules use `socket cgroupv2`, so they need cgroup v2 and a kernel of
  5.13 or later, and they only apply to the host's own processes: forwarded
  traffic has no socket. A cgroup that does not exist yet, because its service
  is not running, is reported and its rules stay inactive; the daemon checks
  every few seconds and reloads the table when it appears.
- Always allowed, before the policy: loopback, IPv6 link-local and multicast
  (neighbour discovery, MLD) and IPv4 multicast (IGMP). Refusing those breaks
  the host's own networking and none of it leaves the link. Plain ICMP is not
  in the policy language yet, so outbound ping is refused.
- By default only the host's own output chain is filtered. `-forward` adds a
  chain on the forward hook so containers, and anything else this host routes,
  get the same policy; traffic that stays on a docker bridge is left alone.
  Pull your images before turning it on, or allow the registry.

### Running it as a service

```
$ sudo cp egresswall /usr/local/bin/
$ sudo mkdir -p /etc/egresswall && sudo cp learned.yaml /etc/egresswall/policy.yaml
$ sudo cp contrib/egresswall.service /etc/systemd/system/
$ sudo systemctl daemon-reload && sudo systemctl enable --now egresswall
$ journalctl -u egresswall -f
```

The unit stops the daemon with SIGINT, which removes the table, and restarts
it after a crash so the address sets get fed again before they expire.

## Policy

```yaml
version: 1
default: deny

deny:
  - name: cloud-metadata
    cidrs: ["169.254.169.254"]

allow:
  - name: dns
    ports: ["53"]
    proto: udp
  - name: package-registries
    domains: ["registry.npmjs.org", "*.pypi.org", "proxy.golang.org"]
    ports: ["443"]
  - name: internal
    cidrs: ["10.0.0.0/8"]
```

A rule matches when the destination hits one of its domains **or** one of its
CIDRs, and the port and protocol fit. A rule with a `cgroup` only matches
sockets opened from that cgroup v2 path or anything below it, so "only the app
may reach the database" is one rule:

```yaml
  - name: app-db
    cidrs: ["10.0.0.5"]
    ports: ["5432"]
    cgroup: system.slice/app.service
```

`learn` tells you where to draw those lines: every rule it writes says which
cgroups the connections came from, busiest first, e.g.
`from system.slice/app.service (412), system.slice/cron.service (3)`. A rule with neither domains nor CIDRs
matches any host, which is how you allow DNS to wherever the resolver is.
`*.example.com` matches subdomains only; write `example.com` too if you mean the
apex. Unknown keys in the file are an error, not a silent no-op.

Try it without root, on any OS:

```
$ egresswall check -policy examples/egresswall.yaml registry.npmjs.org:443
allow  registry.npmjs.org:443  domain registry.npmjs.org  (rule package-registries)

$ egresswall check -policy examples/egresswall.yaml -ip 169.254.169.254 github.com:443
deny  github.com:443  ip 169.254.169.254 in 169.254.169.254/32  (rule cloud-metadata)
```

`check` exits 0 on allow and 1 on deny, so it works in a shell condition and in
CI ("does the policy we are about to ship still allow the registry").

## What it will not catch

Honest list, because an egress filter that oversells itself is worse than none:

- **DNS over HTTPS/TLS to an allowed host.** If `dns.google` is on the list, a
  process can resolve anything through it and connect by IP. Do not allow it.
- **Allowed hosts that store arbitrary data.** If `*.githubusercontent.com` or an
  S3 endpoint is allowed, an attacker can exfiltrate through them. Keep allow rules
  as narrow as the workload lets you.
- **Learn sees a sample, not the truth.** A weekly cron job that never ran during
  the learn window is not in the policy. Learn for long enough, read the file,
  and start `enforce` in dry-run.
- **Shared CDN addresses.** An allowed name and a hostile one can resolve to the
  same edge IP. The daemon allows the IP because an allowed name resolved to it;
  that is a known weakness of every DNS-driven allowlist, and the reason
  per-process attribution is on the roadmap.

## Roadmap

- More alert sinks than a webhook, if anyone asks for one.
- An `nftables` chain per policy file, so two policies can coexist.

## License

MIT

<details>
<summary>🇹🇷 Türkçe</summary>

`egresswall`, sıradan Linux sunucuları için öğrenen modlu bir giden-trafik
firewall'udur. `learn` modunda makinenin fiilen konuştuğu domain ve port'ları bir
policy dosyasına yazar; `enforce` modunda listenin dışını keser ve loglar.
Amaç, ele geçirilmiş bir bağımlılığın çaldığı token'ı dışarı gönderdiği ilk
bağlantıyı durdurmaktır. Ayrıntı için [README.tr.md](README.tr.md).

</details>
