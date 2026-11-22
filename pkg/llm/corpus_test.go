// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBenignCorpus: requests as SDKs, gateways and model servers send them
// (testdata/benign/<format>/) are well-formed, read as encoding/json reads
// them, and pass checks sized for them: a check that fails one is a false
// positive.
func TestBenignCorpus(t *testing.T) {
	rules, err := Compile(Config{MaxPromptBytes: 1 << 20, MaxMessages: 1000, MaxOutputTokens: 10000, MaxChoices: 1})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range Formats {
		files, err := filepath.Glob(filepath.Join("testdata", "benign", f.String(), "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < 3 {
			t.Errorf("%s: %d bodies", f, len(files))
		}
		for _, file := range files {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			n++
			var req Request
			if !Parse(body, f, &req) {
				t.Errorf("%s: malformed at %d: %s", file, req.Offset, req.Why)
				continue
			}
			if got := rules.Check(body, &req, 0); got.Check != CheckNone {
				t.Errorf("%s: %s", file, got.Check)
			}
			want, err := refRead(body, f)
			if err != nil {
				t.Errorf("%s: reference: %v", file, err)
				continue
			}
			if req.PromptBytes != want.prompt || req.Messages != want.messages || string(req.Model()) != want.model {
				t.Errorf("%s: prompt %d, messages %d, model %q; reference %d, %d, %q", file, req.PromptBytes, req.Messages, req.Model(),
					want.prompt, want.messages, want.model)
			}
			if req.PromptBytes == 0 || req.Messages == 0 || !req.HasModel {
				t.Errorf("%s: nothing read: %+v", file, req)
			}
		}
	}
	t.Logf("%d benign bodies", n)
}
