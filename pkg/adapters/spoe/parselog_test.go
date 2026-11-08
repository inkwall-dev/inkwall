// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package spoe

import (
	"net/http"
	"strings"
	"testing"
)

// The errors of a request the agent can't read name the field, never its
// value: a header can carry a secret, and they're logged.
func TestParseErrorsHaveNoValues(t *testing.T) {
	enc := func(kv ...string) []byte {
		var b []byte
		for _, s := range append(kv, "", "") {
			b = appendVarint(b, uint64(len(s)))
			b = append(b, s...)
		}
		return b
	}
	errs := map[string]error{}
	_, _, errs["host"] = parseHeaders(enc("Host", "shop SECRET"))
	_, _, errs["header name"] = parseHeaders(enc("x SECRET", "v", "Host", "shop.example.com"))
	_, _, errs["header value"] = parseHeaders(enc("x-api-key", "a\x00SECRET", "Host", "shop.example.com"))
	_, errs["version"] = protoName("SECRET")
	_, _, errs["content-length"] = bodyLength(http.Header{"Content-Length": {"SECRET"}})
	for name, err := range errs {
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: error %q has the value", name, err)
		}
	}
}
