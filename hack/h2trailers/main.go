// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command h2trailers posts a form body followed by a trailer over HTTP/2
// without TLS (prior knowledge), and prints the response's status code.
// curl can't send request trailers; the kind end-to-end test uses this to
// check that a body with trailers is inspected (#235).
//
//	go run ./hack/h2trailers -host eg.example.com http://127.0.0.1:18091/ 'q=1%27%20OR%20%271%27%3D%271'
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	host := flag.String("host", "", "the Host (:authority) to send")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: h2trailers [-host HOST] URL BODY")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	code, err := post(flag.Arg(0), *host, flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "h2trailers:", err)
		os.Exit(1)
	}
	fmt.Println(code)
}

func post(url, host, body string) (int, error) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Protocols: &protocols}}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Sent after the body: Envoy then passes the body to ext_proc without
	// end_of_stream.
	req.Trailer = http.Header{"X-Checksum": {"0"}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		return 0, fmt.Errorf("answered over %s, want HTTP/2", resp.Proto)
	}
	return resp.StatusCode, nil
}
