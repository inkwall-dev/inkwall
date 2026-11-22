// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command mmdbgen writes a small country database for the e2e tests
// (design 0011 §10): an IPv6 MMDB with MaxMind's IPv4 aliases, mapping the
// prefixes it is given to their countries.
//
//	go run ./operator/internal/geo/mmdbtest/mmdbgen -epoch 1700000000 198.51.100.0/24=XA 203.0.113.0/24=XB > db.mmdb
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
)

func main() {
	epoch := flag.Uint64("epoch", 1_700_000_000, "the database's build_epoch (Unix seconds)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mmdbgen [-epoch N] PREFIX=CC ... > db.mmdb")
		flag.PrintDefaults()
	}
	flag.Parse()
	db := mmdbtest.DB{Type: "Inkwall-E2E-Country", BuildEpoch: *epoch, Aliases: mmdbtest.MaxMindAliases}
	for _, arg := range flag.Args() {
		prefix, code, ok := strings.Cut(arg, "=")
		p, err := netip.ParsePrefix(prefix)
		if !ok || err != nil || len(code) != 2 {
			fmt.Fprintf(os.Stderr, "mmdbgen: %q is not PREFIX=CC\n", arg)
			os.Exit(2)
		}
		db.Networks = append(db.Networks, mmdbtest.Network{Prefix: p, Record: &mmdbtest.Record{Country: code}})
	}
	out, err := db.Bytes()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mmdbgen:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintln(os.Stderr, "mmdbgen:", err)
		os.Exit(1)
	}
}
