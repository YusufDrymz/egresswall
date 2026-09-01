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

> **Status: early.** `learn` and `check` work (Linux, root for `learn`; the
> policy engine runs anywhere). `enforce` is next. Nothing here is running in
> production yet.

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
$ sudo egresswall enforce -policy egresswall.yaml  # drop the rest, log it (soon)
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
CIDRs, and the port and protocol fit. A rule with neither domains nor CIDRs
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

- `enforce`: nftables table owned by egresswall, DNS-driven IP sets with TTL,
  nflog for refusals, dry-run mode that logs without dropping.
- Per-process and per-cgroup rules, so "only the app may reach the database"
  is expressible.
- Alert sinks: journald first, then a webhook.

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
