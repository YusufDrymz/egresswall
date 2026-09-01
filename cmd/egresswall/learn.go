package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/YusufDrymz/egresswall/internal/capture"
	"github.com/YusufDrymz/egresswall/internal/dnswatch"
	"github.com/YusufDrymz/egresswall/internal/learn"
	"github.com/YusufDrymz/egresswall/internal/packet"
)

// Applications hold on to resolved addresses far longer than the DNS TTL;
// five minutes keeps most of their later connections attributable to a name.
const learnMinTTL = 5 * time.Minute

func runLearn(args []string) error {
	fs := flag.NewFlagSet("learn", flag.ExitOnError)
	out := fs.String("out", "egresswall.yaml", `where to write the policy ("-" for stdout)`)
	dur := fs.Duration("duration", 0, "stop after this long (default: until interrupted)")
	quiet := fs.Bool("quiet", false, "do not print destinations as they are discovered")
	fs.Parse(args)

	src, err := capture.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}

	dns := dnswatch.New(learnMinTTL)
	obs := learn.NewObserver(dns)
	if !*quiet {
		obs.OnNew = func(e learn.Entry) {
			fmt.Fprintf(os.Stderr, "new  %s:%d %s\n", e.Host, e.Port, e.Proto)
		}
	}
	started := time.Now()
	fmt.Fprintf(os.Stderr, "egresswall: learning, writing to %s on stop\n", *out)

	lastSweep := started
	for ctx.Err() == nil {
		frame, outgoing, err := src.Read()
		if errors.Is(err, capture.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		now := time.Now()
		if p, err := packet.Parse(frame); err == nil {
			obs.Packet(p, outgoing, now)
		}
		if now.Sub(lastSweep) > 30*time.Second {
			obs.Sweep(now)
			dns.Purge(now)
			lastSweep = now
		}
	}

	entries := obs.Entries()
	var w io.Writer = os.Stdout
	if *out != "-" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := learn.WritePolicy(w, entries, started, time.Now()); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "egresswall: %d destinations after %s, policy written to %s\n",
		len(entries), time.Since(started).Round(time.Second), *out)
	return nil
}
