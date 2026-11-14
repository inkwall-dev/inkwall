// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package forwardauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The errors of a forward-auth request the engine can't read name the
// header, never its value: a URI's query or a header can carry a secret, and
// they're logged at error level (#522, #620).
func TestParseErrorsHaveNoValues(t *testing.T) {
	for name, set := range map[string]map[string]string{
		"method": {"X-Forwarded-Method": "GET SECRET", "X-Forwarded-Uri": "/"},
		"uri":    {"X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/%zz?token=SECRET"},
		"host":   {"X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/", "X-Forwarded-Host": "shop.example.com/SECRET"},
	} {
		r := httptest.NewRequest("GET", Path, nil)
		for k, v := range set {
			r.Header.Set(k, v)
		}
		_, _, err := (&Handler{}).toRequest(r)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: error %q has the value", name, err)
		}
	}
}
