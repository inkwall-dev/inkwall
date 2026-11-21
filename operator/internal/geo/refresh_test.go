// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"context"
	"strings"
	"testing"

	"github.com/inkwall-dev/inkwall/operator/internal/geo/mmdbtest"
)

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	db := func(epoch uint64, code string) []byte {
		return must(mmdbtest.DB{BuildEpoch: epoch, Networks: []mmdbtest.Network{nw("1.0.0.0/8", cc(code))}}.Bytes())
	}
	src := func(b []byte) *Source { return &Source{Data: b} }
	stored, _ := compileOK(t, db(1000, "AU"))
	notFound := fail(ReasonNotFound, "database file /var/lib/inkwall/geo/x.mmdb not found")
	invalid := fail(ReasonInvalid, "not a valid MaxMind DB")

	for name, c := range map[string]struct {
		src     *Source
		srcErr  error
		stored  *Table
		table   *Table // nil: a new one, or none when !isNew
		isNew   bool
		reason  string
		message string
	}{
		"first":                 {src: src(db(1000, "AU")), isNew: true, reason: ReasonLoaded, message: "Test-Country built"},
		"unchanged":             {src: src(db(1000, "AU")), stored: stored, table: stored, reason: ReasonLoaded},
		"newer":                 {src: src(db(2000, "DE")), stored: stored, isNew: true, reason: ReasonLoaded},
		"older":                 {src: src(db(999, "DE")), stored: stored, table: stored, reason: ReasonLoaded, message: "older than the stored table"},
		"same epoch, new hash":  {src: src(db(1000, "DE")), stored: stored, isNew: true, reason: ReasonLoaded, message: "same time"},
		"missing, stored":       {srcErr: notFound, stored: stored, table: stored, reason: ReasonLoaded, message: "the stored table is in use"},
		"missing, none":         {srcErr: notFound, reason: ReasonNotFound},
		"invalid, stored":       {src: src([]byte("junk")), stored: stored, table: stored, reason: ReasonInvalid, message: "keep the last good table"},
		"invalid source, none":  {srcErr: invalid, reason: ReasonInvalid},
		"read error, stored":    {srcErr: invalid, stored: stored, table: stored, reason: ReasonInvalid, message: "keep the last good table"},
		"no country, stored":    {src: src(must(mmdbtest.DB{BuildEpoch: 3000, Networks: []mmdbtest.Network{nw("1.0.0.0/8", &mmdbtest.Record{Continent: "EU"})}}.Bytes())), stored: stored, table: stored, reason: ReasonNoCountryData},
		"empty source":          {src: src(nil), reason: ReasonInvalid},
		"empty source, nothing": {reason: ReasonInvalid},
	} {
		o := Refresh(ctx, c.src, c.srcErr, c.stored)
		if o.Reason != c.reason || o.New != c.isNew {
			t.Errorf("%s: reason %s, new %v; want %s, %v (%s)", name, o.Reason, o.New, c.reason, c.isNew, o.Message)
		}
		switch {
		case c.table != nil && o.Table != c.table:
			t.Errorf("%s: published %v, want the stored table", name, o.Table)
		case c.isNew && (o.Table == nil || o.Table == c.stored):
			t.Errorf("%s: no new table", name)
		case c.table == nil && !c.isNew && o.Table != nil:
			t.Errorf("%s: published a table", name)
		}
		if !strings.Contains(o.Message, c.message) {
			t.Errorf("%s: message %q, want %q in it", name, o.Message, c.message)
		}
		if (o.Err != nil) != (c.reason != ReasonLoaded) {
			t.Errorf("%s: error %v for reason %s", name, o.Err, o.Reason)
		}
	}
}
