// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command mcpclient drives an MCP server over stdio for the kind e2e
// (hack/kind/mcp-e2e.sh): it starts the command after --, initializes, and
// lists the tools (-list), reads a resource (-read URI), or calls a tool
// (-tool NAME -args JSON), printing the result as JSON. It exits 1 on a
// tool error, with its text on standard error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	list := flag.Bool("list", false, "list the tools: name and readOnlyHint, one per line")
	read := flag.String("read", "", "read this resource and print its text")
	tool := flag.String("tool", "", "call this tool")
	args := flag.String("args", "{}", "the tool's arguments, as a JSON object")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: mcpclient [-list | -read URI | -tool NAME -args JSON] -- COMMAND [ARGS...]")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// #nosec G204 -- the command the e2e script gives
	cmd := exec.CommandContext(ctx, flag.Arg(0), flag.Args()[1:]...)
	cmd.Stderr = os.Stderr
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "mcpclient", Version: "e2e"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		fail(err)
	}
	defer func() { _ = cs.Close() }()
	switch {
	case *list:
		for t, err := range cs.Tools(ctx, nil) {
			if err != nil {
				fail(err)
			}
			fmt.Println(t.Name, t.Annotations != nil && t.Annotations.ReadOnlyHint)
		}
	case *read != "":
		res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: *read})
		if err != nil {
			fail(err)
		}
		for _, c := range res.Contents {
			fmt.Print(c.Text)
		}
	case *tool != "":
		var a map[string]any
		if err := json.Unmarshal([]byte(*args), &a); err != nil {
			fail(fmt.Errorf("-args: %w", err))
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: a})
		if err != nil {
			fail(err)
		}
		if res.IsError {
			for _, c := range res.Content {
				if t, ok := c.(*mcp.TextContent); ok {
					fmt.Fprintln(os.Stderr, t.Text)
				}
			}
			_ = cs.Close()
			os.Exit(1)
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			fail(err)
		}
		fmt.Println(string(b))
	default:
		fail(fmt.Errorf("give -list, -read or -tool"))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mcpclient:", err)
	os.Exit(1)
}
