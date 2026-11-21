// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Outcome is what a refresh decided: the table to publish, and the
// GeoDatabaseReady condition's reason and message.
type Outcome struct {
	// Table is the table the bundle names: the new one, or the stored one
	// kept; nil when there is none.
	Table *Table
	// New is whether Table was just compiled, and has to be stored.
	New bool
	// Reason is the condition's reason: Loaded, or the source's problem.
	// Empty for a transient error (the API server's, a cancelled context):
	// the condition stays as it is, and the refresh is retried.
	Reason string
	// Message is the condition's message.
	Message string
	// Err is the source's problem, if any.
	Err error
}

// Transient reports whether the refresh failed for a reason that says
// nothing about the database: retry it, and leave the condition.
func (o Outcome) Transient() bool { return o.Err != nil && o.Reason == "" }

// Refresh decides what to publish from a database source (or the error
// reading it) and the stored table, nil if there is none (design 0011
// §4.2):
//
//   - an unchanged source keeps the stored table, without compiling;
//   - a source built before the stored table, or a missing one, keeps the
//     stored table, and that is Loaded, not an error: each replica's
//     updater has its own copy, and a leader change would otherwise flip
//     the cluster between two databases;
//   - a source built at the same second with another hash is taken;
//   - a source that fails keeps the stored table, with the failure's
//     reason: engines keep enforcing the last good table.
//
// The source is read only inside Compile, where a fault of a mapped file
// truncated under it is recovered.
func Refresh(ctx context.Context, src *Source, srcErr error, stored *Table) Outcome {
	if srcErr == nil && src == nil {
		srcErr = fail(ReasonInvalid, "the database is empty")
	}
	if srcErr != nil {
		return failed(srcErr, stored)
	}
	t, err := Compile(ctx, src.Data, stored)
	switch {
	case errors.Is(err, ErrUnchanged):
		return Outcome{Table: stored, Reason: ReasonLoaded, Message: describe(stored)}
	case errors.Is(err, ErrOlder):
		return Outcome{Table: stored, Reason: ReasonLoaded, Message: describe(stored) + "; " + err.Error() + ": the stored table is in use"}
	case err != nil:
		return failed(err, stored)
	}
	msg := describe(t)
	if t.BadCodes > 0 {
		msg += fmt.Sprintf("; %d networks with a code that isn't two letters have no country", t.BadCodes)
	}
	if stored != nil && t.BuildEpoch == stored.BuildEpoch {
		msg += "; built at the same time as the stored table, with another hash: taken"
	}
	return Outcome{Table: t, New: true, Reason: ReasonLoaded, Message: msg}
}

// failed is the outcome of a source that can't be read or compiled.
func failed(err error, stored *Table) Outcome {
	reason := ReasonOf(err)
	switch {
	case reason == "":
		return Outcome{Table: stored, Err: err, Message: err.Error()}
	case stored == nil:
		return Outcome{Reason: reason, Message: err.Error(), Err: err}
	case reason == ReasonNotFound:
		return Outcome{Table: stored, Reason: ReasonLoaded, Message: describe(stored) + "; " + err.Error() + ": the stored table is in use"}
	}
	return Outcome{Table: stored, Reason: reason, Err: err,
		Message: err.Error() + "; engines keep the last good table, " + describe(stored)}
}

// describe names a table for a condition's message.
func describe(t *Table) string {
	return fmt.Sprintf("%s built %s, %d ranges, %d KiB compressed", t.DatabaseType, t.Built().Format(time.DateOnly), t.Ranges, (len(t.Compressed)+1023)>>10)
}
