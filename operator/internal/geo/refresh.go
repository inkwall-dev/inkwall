// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package geo

import (
	"context"
	"crypto/sha256"
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
	Reason string
	// Message is the condition's message.
	Message string
	// Err is the source's problem, if any.
	Err error
}

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
func Refresh(ctx context.Context, src *Source, srcErr error, stored *Table) Outcome {
	if srcErr == nil {
		if src == nil || len(src.Data) == 0 {
			srcErr = fail(ReasonInvalid, "the database is empty")
		}
	}
	if srcErr != nil {
		reason := ReasonOf(srcErr)
		if stored == nil {
			return Outcome{Reason: reason, Message: srcErr.Error(), Err: srcErr}
		}
		if reason == ReasonNotFound {
			return Outcome{Table: stored, Reason: ReasonLoaded, Message: describe(stored) + "; " + srcErr.Error() + ": the stored table is in use"}
		}
		return Outcome{Table: stored, Reason: reason, Err: srcErr,
			Message: srcErr.Error() + "; engines keep the last good table, " + describe(stored)}
	}
	sum := sha256.Sum256(src.Data)
	if stored != nil && sum == stored.DatabaseSHA256 {
		return Outcome{Table: stored, Reason: ReasonLoaded, Message: describe(stored)}
	}
	t, err := Compile(ctx, src.Data, stored)
	switch {
	case errors.Is(err, ErrOlder):
		return Outcome{Table: stored, Reason: ReasonLoaded, Message: describe(stored) + "; " + err.Error() + ": the stored table is in use"}
	case err != nil && stored != nil:
		return Outcome{Table: stored, Reason: ReasonOf(err), Err: err,
			Message: err.Error() + "; engines keep the last good table, " + describe(stored)}
	case err != nil:
		return Outcome{Reason: ReasonOf(err), Message: err.Error(), Err: err}
	}
	msg := describe(t)
	if t.BadCodes > 0 {
		msg += fmt.Sprintf("; %d records with a code that isn't two letters have no country", t.BadCodes)
	}
	if stored != nil && t.BuildEpoch == stored.BuildEpoch {
		msg += "; built at the same time as the stored table, with another hash: taken"
	}
	return Outcome{Table: t, New: true, Reason: ReasonLoaded, Message: msg}
}

// describe names a table for a condition's message.
func describe(t *Table) string {
	return fmt.Sprintf("%s built %s, %d ranges, %d KiB compressed", t.DatabaseType, t.Built().Format(time.DateOnly), t.Ranges, (len(t.Compressed)+1023)>>10)
}
