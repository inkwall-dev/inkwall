// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/compile"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/grpcschematest"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema/load"
)

// TestCompileSizeWithSource: the bound on the compiled size is on the
// schema the bundle carries, with its id and source, as engines check
// it: a set just under it without them, named by a long source, is
// refused by the operator, never by every engine.
func TestCompileSizeWithSource(t *testing.T) {
	// The longest source: a namespace, a ConfigMap name and a key.
	long := strings.Repeat("n", 63) + "/" + strings.Repeat("c", 253) + "/" + strings.Repeat("k", 253)
	data := grpcschematest.AtBound(t, len(long)-1)
	cache := compile.NewCache()
	for _, c := range []struct {
		name    string
		compile func(source string) (*grpcschema.Schema, error)
	}{
		{"Compile", func(source string) (*grpcschema.Schema, error) {
			s, err := compile.Compile(data, source)
			if err != nil {
				return nil, err
			}
			return load.Load(s)
		}},
		{"Cache", func(source string) (*grpcschema.Schema, error) {
			s, _, err := cache.Compile(data, source)
			if err != nil {
				return nil, err
			}
			if proto.Size(s) > grpcschema.MaxCompiledBytes {
				t.Errorf("%d bytes", proto.Size(s))
			}
			return load.Load(s)
		}},
	} {
		if _, err := c.compile("x"); err != nil {
			t.Fatalf("%s, a short source: %v", c.name, err)
		}
		if _, err := c.compile(long); err == nil || !strings.Contains(err.Error(), "with its id and source") {
			t.Fatalf("%s, a long source: %v", c.name, err)
		}
	}
}
