// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
)

// loadRequests turns the input flags into check requests.
func loadRequests(cfg testConfig) ([]*enginev1.CheckRequest, error) {
	switch {
	case cfg.url != "":
		in, err := fromCommandLine(cfg)
		if err != nil {
			return nil, err
		}
		return []*enginev1.CheckRequest{in}, nil
	case cfg.requestFile != "":
		f, err := os.Open(filepath.Clean(cfg.requestFile))
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return fromRawHTTP(f)
	default:
		b, err := os.ReadFile(filepath.Clean(cfg.harFile))
		if err != nil {
			return nil, err
		}
		return fromHAR(b)
	}
}

// fromCommandLine builds a request the way curl would send it.
func fromCommandLine(cfg testConfig) (*enginev1.CheckRequest, error) {
	scheme, authority, rawURI, err := splitURL(cfg.url)
	if err != nil {
		return nil, err
	}
	var body []byte
	if cfg.data != "" {
		if path, ok := strings.CutPrefix(cfg.data, "@"); ok {
			if body, err = os.ReadFile(filepath.Clean(path)); err != nil {
				return nil, err
			}
		} else {
			body = []byte(cfg.data)
		}
	}
	method := cfg.method
	if method == "" {
		method = http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
	}

	// curl's defaults, unless overridden with -H.
	headers := http.Header{}
	headers.Set("User-Agent", "inkwallctl")
	headers.Set("Accept", "*/*")
	if body != nil {
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
		headers.Set("Content-Length", strconv.Itoa(len(body)))
	}
	for _, h := range cfg.headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("-H %q: want \"Name: value\"", h)
		}
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "Host") {
			authority = strings.TrimSpace(value)
			continue
		}
		headers.Set(name, strings.TrimSpace(value))
	}
	return &enginev1.CheckRequest{
		Method:    method,
		Scheme:    scheme,
		Authority: authority,
		RawUri:    rawURI,
		Headers:   toHeaders(headers),
		Body:      body,
		ClientIp:  "127.0.0.1",
	}, nil
}

// splitURL splits an absolute URL without parsing or re-encoding its path
// and query, so payloads are checked exactly as written. A fragment is
// dropped, as clients do not send it.
func splitURL(raw string) (scheme, authority, rawURI string, err error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", "", "", fmt.Errorf("URL %q: want http://host/path", raw)
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", "", fmt.Errorf("URL %q: scheme must be http or https", raw)
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	i := strings.IndexAny(rest, "/?")
	if i < 0 {
		return scheme, rest, "/", nil
	}
	authority, rawURI = rest[:i], rest[i:]
	if rawURI[0] == '?' {
		rawURI = "/" + rawURI
	}
	if authority == "" {
		return "", "", "", fmt.Errorf("URL %q has no host", raw)
	}
	return scheme, authority, rawURI, nil
}

// fromRawHTTP reads one or more HTTP/1.x requests, e.g. copied from a proxy
// log or Burp.
func fromRawHTTP(r io.Reader) ([]*enginev1.CheckRequest, error) {
	br := bufio.NewReader(r)
	var out []*enginev1.CheckRequest
	for {
		// Blank lines between requests are allowed.
		for {
			b, err := br.Peek(1)
			if err != nil || (b[0] != '\r' && b[0] != '\n') {
				break
			}
			_, _ = br.ReadByte()
		}
		if _, err := br.Peek(1); errors.Is(err, io.EOF) {
			break
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", len(out)+1, err)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("request %d body: %w", len(out)+1, err)
		}
		rawURI, authority, scheme := req.RequestURI, req.Host, "http"
		if !strings.HasPrefix(rawURI, "/") && rawURI != "*" {
			// Absolute form: GET http://host/path HTTP/1.1
			if scheme, authority, rawURI, err = splitURL(rawURI); err != nil {
				return nil, fmt.Errorf("request %d: %w", len(out)+1, err)
			}
		}
		// net/http moves these out of the header map; rules look for them.
		headers := req.Header.Clone()
		if len(req.TransferEncoding) > 0 {
			headers["Transfer-Encoding"] = req.TransferEncoding
		}
		in := &enginev1.CheckRequest{
			Method:    req.Method,
			Scheme:    scheme,
			Authority: authority,
			RawUri:    rawURI,
			Headers:   toHeaders(headers),
			ClientIp:  "127.0.0.1",
			Protocol:  req.Proto,
		}
		if len(body) > 0 {
			in.Body = body
		}
		out = append(out, in)
	}
	if len(out) == 0 {
		return nil, errors.New("no request in the file")
	}
	return out, nil
}

// har is the subset of HTTP Archive 1.2 that describes requests.
type har struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method      string `json:"method"`
				URL         string `json:"url"`
				HTTPVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				PostData *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Encoding string `json:"encoding"` // non-standard, used by some exporters
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func fromHAR(b []byte) ([]*enginev1.CheckRequest, error) {
	var doc har
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse HAR: %w", err)
	}
	if len(doc.Log.Entries) == 0 {
		return nil, errors.New("no requests in the HAR file")
	}
	out := make([]*enginev1.CheckRequest, 0, len(doc.Log.Entries))
	for i, e := range doc.Log.Entries {
		req := e.Request
		scheme, authority, rawURI, err := splitURL(req.URL)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		in := &enginev1.CheckRequest{
			Method:    req.Method,
			Scheme:    scheme,
			Authority: authority,
			RawUri:    rawURI,
			ClientIp:  "127.0.0.1",
			Protocol:  harProtocol(req.HTTPVersion),
		}
		for _, h := range req.Headers {
			// HTTP/2 pseudo-headers; the authority is already in the URL.
			if strings.HasPrefix(h.Name, ":") || strings.EqualFold(h.Name, "Host") {
				continue
			}
			in.Headers = append(in.Headers, &enginev1.Header{Name: h.Name, Value: h.Value})
		}
		if pd := req.PostData; pd != nil && pd.Text != "" {
			if pd.Encoding == "base64" {
				if in.Body, err = base64.StdEncoding.DecodeString(pd.Text); err != nil {
					return nil, fmt.Errorf("entry %d body: %w", i+1, err)
				}
			} else {
				in.Body = []byte(pd.Text)
			}
		}
		out = append(out, in)
	}
	return out, nil
}

// harProtocol maps a HAR httpVersion ("HTTP/1.1", "h2", "http/2.0") to the
// form the engine uses.
func harProtocol(v string) string {
	switch strings.ToLower(v) {
	case "h2", "http/2", "http/2.0":
		return "HTTP/2.0"
	case "h3", "http/3", "http/3.0":
		return "HTTP/3.0"
	case "http/1.0":
		return "HTTP/1.0"
	default:
		return "HTTP/1.1"
	}
}

// toHeaders converts h in name order. Values that are not valid UTF-8 go in
// raw_value: protobuf strings must be UTF-8.
func toHeaders(h http.Header) []*enginev1.Header {
	var out []*enginev1.Header
	for _, name := range slices.Sorted(maps.Keys(h)) {
		for _, v := range h[name] {
			if utf8.ValidString(v) {
				out = append(out, &enginev1.Header{Name: name, Value: v})
			} else {
				out = append(out, &enginev1.Header{Name: name, RawValue: []byte(v)})
			}
		}
	}
	return out
}
