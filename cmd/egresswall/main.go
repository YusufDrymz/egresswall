// egresswall: learn where a Linux host talks, then refuse everything else.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/YusufDrymz/egresswall/internal/policy"
)

const version = "0.0.1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "check":
		err = runCheck(os.Args[2:])
	case "validate":
		err = runValidate(os.Args[2:])
	case "learn", "enforce":
		err = notYet(os.Args[1])
	case "version":
		fmt.Println("egresswall", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "egresswall: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "egresswall:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: egresswall <command> [flags]

  check     ask the policy about one destination, e.g. check registry.npmjs.org:443
  validate  parse a policy file and report every problem in it
  learn     watch outbound traffic and write a policy (linux, not implemented yet)
  enforce   apply a policy with nftables (linux, not implemented yet)
  version

`)
}

func notYet(cmd string) error {
	return fmt.Errorf("%s is not implemented yet; the policy engine is, see 'egresswall check'", cmd)
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("policy", "egresswall.yaml", "policy file")
	fs.Parse(args)
	if _, err := policy.Load(*path); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

// check exits 0 on allow and 1 on deny so it can sit in a shell condition.
func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("policy", "egresswall.yaml", "policy file")
	proto := fs.String("proto", "tcp", "tcp or udp")
	ipFlag := fs.String("ip", "", "resolved address to check alongside the name (no lookup is done)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("check wants exactly one host:port")
	}
	set, err := policy.Load(*path)
	if err != nil {
		return err
	}
	dest, err := parseDest(fs.Arg(0), *ipFlag, *proto)
	if err != nil {
		return err
	}
	d := set.Evaluate(dest)
	fmt.Printf("%s  %s  %s", d.Verdict, fs.Arg(0), d.Reason)
	if d.Rule != "" {
		fmt.Printf("  (rule %s)", d.Rule)
	}
	fmt.Println()
	if d.Verdict == policy.Deny {
		os.Exit(1)
	}
	return nil
}

func parseDest(hostport, ip, proto string) (policy.Dest, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return policy.Dest{}, fmt.Errorf("want host:port, got %q", hostport)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return policy.Dest{}, fmt.Errorf("bad port in %q", hostport)
	}
	d := policy.Dest{Port: uint16(port), Proto: proto}
	if a, err := netip.ParseAddr(host); err == nil {
		d.IP = a
	} else {
		d.Domain = host
	}
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return policy.Dest{}, fmt.Errorf("bad -ip %q", ip)
		}
		d.IP = a
	}
	return d, nil
}
