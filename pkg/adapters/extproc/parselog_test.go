// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"net/netip"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// The errors of a request the adapter can't read name the field, never its
// value: a path's query or a header can carry a secret, and they're logged.
func TestParseErrorsHaveNoValues(t *testing.T) {
	ok := map[string]string{":method": "GET", ":path": "/", ":authority": "shop.example.com", ":scheme": "https"}
	for name, bad := range map[string][2]string{
		"path":      {":path", "https://shop.example.com/?token=SECRET"},
		"method":    {":method", "GET SECRET"},
		"authority": {":authority", "shop SECRET"},
		"scheme":    {":scheme", "SECRET"},
		"header":    {"x-SECRET name", "v"},
	} {
		var hs []*corev3.HeaderValue
		for k, v := range ok {
			if k != bad[0] {
				hs = append(hs, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
			}
		}
		hs = append(hs, &corev3.HeaderValue{Key: bad[0], RawValue: []byte(bad[1])})
		_, _, err := (&Server{}).toRequest(&extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}}, netip.MustParseAddr("10.0.0.1"), "HTTP/1.1")
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: error %q has the value", name, err)
		}
	}
}
