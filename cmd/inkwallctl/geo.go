// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/bundle"
	"github.com/inkwall-dev/inkwall/pkg/bundlesecret"
	"github.com/inkwall-dev/inkwall/pkg/geo"
)

const geoUsage = "usage: inkwallctl geo lookup [flags] IP ..."

// GeoLookup is one address's country, the shape of -o json.
type GeoLookup struct {
	IP string `json:"ip"`
	// Country is the code, "" without one.
	Country string `json:"country"`
	// Result is country, private, unknown: as the engines' metrics say.
	Result string `json:"result"`
}

// runGeo looks addresses up in the country table the published bundle
// names, read from its Secrets and checked against the bundle's hash of it,
// so a user can test an address before blocking it (design 0011 §8). The
// bundle's signature isn't verified: a diagnostic, as the engines' own
// verified copy decides.
func runGeo(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "lookup" {
		fmt.Fprintln(stderr, geoUsage)
		return 2
	}
	fs := flag.NewFlagSet("geo lookup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, geoUsage)
		fmt.Fprintln(stderr, "Prints each address's country, as the engines see it, from the country table the published bundle names. Read only.")
		fmt.Fprintln(stderr, "The table is checked against the bundle's hash of it; the bundle's signature isn't verified: the engines verify their own copy.")
		fs.PrintDefaults()
	}
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	kctx := fs.String("context", "", "kubeconfig context (default: the current one)")
	namespace := fs.String("namespace", "inkwall-system", "the operator's namespace")
	output := fs.String("o", "text", "output: text or json")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() == 0 || *output != "text" && *output != "json" {
		fmt.Fprintln(stderr, geoUsage)
		return 2
	}
	var addrs []netip.Addr
	for _, s := range fs.Args() {
		a, err := netip.ParseAddr(s)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		addrs = append(addrs, a)
	}
	c, err := newStatusClient(*kubeconfig, *kctx)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	table, err := publishedGeoTable(ctx, c, *namespace)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	out := make([]GeoLookup, 0, len(addrs))
	for _, a := range addrs {
		code, res := table.Lookup(a)
		out = append(out, GeoLookup{IP: a.String(), Country: code.String(), Result: res.String()})
	}
	if *output == "json" {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprintf(stdout, "# %s built %s\n", table.DatabaseType(), table.Built().Format(time.DateOnly))
	for _, l := range out {
		country := l.Country
		if country == "" {
			country = "-"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", l.IP, country, l.Result)
	}
	return 0
}

// publishedGeoTable reads the country table the published bundle names.
func publishedGeoTable(ctx context.Context, c client.Reader, namespace string) (*geo.Table, error) {
	var s corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: bundle.BundleSecret}, &s); err != nil {
		return nil, fmt.Errorf("the bundle Secret: %w", err)
	}
	signed, err := bundle.Read(ctx, c, &s)
	if err != nil {
		return nil, fmt.Errorf("the bundle Secret: %w", err)
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return nil, fmt.Errorf("the bundle: %w", err)
	}
	ref := b.GetGeoTable()
	if ref == nil {
		return nil, fmt.Errorf("bundle %d names no country table: no policy uses spec.geo, or no database is compiled (inkwallctl status)", b.GetVersion())
	}
	var m corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: bundlesecret.Geo.Name}, &m); err != nil {
		return nil, fmt.Errorf("the country table's Secret: %w", err)
	}
	man, err := bundlesecret.Geo.ParseManifest(m.Data[bundlesecret.ManifestKey])
	if err != nil {
		return nil, fmt.Errorf("the country table's Secret: %w", err)
	}
	if !bytes.Equal(man.SHA256Bytes(), ref.GetSha256()) {
		return nil, errors.New("the stored country table isn't the one the bundle names yet: a new database is being published; try again")
	}
	gz, err := bundlesecret.Join(man, func(name string) ([]byte, error) {
		var chunk corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &chunk); err != nil {
			return nil, err
		}
		return chunk.Data[bundlesecret.ChunkKey], nil
	})
	if err != nil {
		return nil, fmt.Errorf("the country table: %w", err)
	}
	return geo.Decode(gz, ref.GetSha256(), ref.GetSize())
}
