// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command wsecho is a WebSocket echo server and a client for it. The kind
// end-to-end test uses both to check that a WebSocket handshake through
// Traefik and Envoy Gateway is inspected: an allowed one upgrades and
// echoes, a denied one gets no upgrade (#276).
//
// The server answers a WebSocket handshake on any path, from any origin,
// and echoes every message; any other request gets 200 "ok".
//
//	wsecho -listen :8080
//
// The client sends one handshake, with the headers given, and prints
// "upgraded" when the server answered 101 Switching Protocols and echoed a
// message (-message, or a greeting), the status code it answered instead
// (403, ...), or "closed CODE" when it closed the WebSocket with that code
// instead of echoing (1008, ...).
//
//	go run ./hack/wsecho -host ws.example.com -origin https://app.example.com 127.0.0.1:18091/chat
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455's Sec-WebSocket-Accept is SHA-1
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	listen := flag.String("listen", "", "serve on this `address` instead of running the client")
	host := flag.String("host", "", "the Host to send")
	origin := flag.String("origin", "", "the Origin to send (none: no Origin header)")
	message := flag.String("message", "", "the text message to send once upgraded (default: a greeting), at most 125 bytes")
	var headers []string
	flag.Func("header", "a `Name: value` header to send (repeatable)", func(s string) error {
		if _, _, ok := strings.Cut(s, ":"); !ok {
			return fmt.Errorf("%q is not Name: value", s)
		}
		headers = append(headers, s)
		return nil
	})
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wsecho -listen ADDR | wsecho [-host HOST] [-origin ORIGIN] [-header 'NAME: VALUE']... HOST:PORT/PATH")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *listen != "" {
		if err := serve(*listen); err != nil {
			fmt.Fprintln(os.Stderr, "wsecho:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	out, err := dial(flag.Arg(0), *host, *origin, *message, headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wsecho:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

// serve echoes WebSocket messages, from any origin.
func serve(addr string) error {
	echo := websocket.Server{
		// The default handshake rejects a missing or unparsable Origin:
		// this server leaves origins to the WAF in front of it.
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler:   func(ws *websocket.Conn) { _, _ = io.Copy(ws, ws) },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			echo.ServeHTTP(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// dial sends a handshake to target (HOST:PORT/PATH) and, once upgraded,
// one text message that must come back.
func dial(target, host, origin, message string, headers []string) (string, error) {
	addr, path, _ := strings.Cut(target, "/")
	path = "/" + path
	if host == "" {
		host = addr
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n", path, host)
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: wsecho\r\n", key)
	if origin != "" {
		fmt.Fprintf(&b, "Origin: %s\r\n", origin)
	}
	for _, h := range headers {
		fmt.Fprintf(&b, "%s\r\n", h)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return "", err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		return fmt.Sprint(resp.StatusCode), nil
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), accept(key); got != want {
		return "", fmt.Errorf("Sec-WebSocket-Accept %q, want %q", got, want)
	}

	msg := message
	if msg == "" {
		msg = "hello " + base64.RawURLEncoding.EncodeToString(nonce[:6])
	}
	if err := writeText(conn, msg); err != nil {
		return "", err
	}
	echoed, closeCode, err := readText(br)
	if err != nil {
		return "", err
	}
	if closeCode != 0 {
		return fmt.Sprintf("closed %d", closeCode), nil
	}
	if echoed != msg {
		return "", fmt.Errorf("echoed %q, want %q", echoed, msg)
	}
	return "upgraded", nil
}

func accept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- RFC 6455
	return base64.StdEncoding.EncodeToString(h[:])
}

// writeText sends msg as one masked text frame, as a client must.
func writeText(w io.Writer, msg string) error {
	if len(msg) > 125 {
		return errors.New("message too long")
	}
	frame := []byte{0x81, 0x80 | byte(len(msg)), 0, 0, 0, 0} // #nosec G115 -- at most 125, checked above
	_, _ = rand.Read(frame[2:6])
	for i := 0; i < len(msg); i++ {
		frame = append(frame, msg[i]^frame[2+i%4])
	}
	_, err := w.Write(frame)
	return err
}

// readText reads one unmasked text frame from the server, or a close
// frame, whose code it returns.
func readText(r io.Reader) (string, int, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", 0, err
	}
	op := head[0] & 0x0f
	if (op != 1 && op != 8) || head[1]&0x80 != 0 {
		return "", 0, fmt.Errorf("unexpected frame %#x %#x", head[0], head[1])
	}
	n := uint64(head[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return "", 0, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		return "", 0, errors.New("frame too long")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", 0, err
	}
	if op == 8 {
		if len(payload) < 2 {
			return "", 1005, nil // no status code
		}
		return "", int(binary.BigEndian.Uint16(payload)), nil
	}
	return string(payload), 0, nil
}
