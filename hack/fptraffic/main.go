// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command fptraffic records the traffic of a real application as a HAR
// file, for the false-positive run (hack/fp-run.sh, make fp-run; #600,
// #707). It plays a few users of the application, each with the requests
// its front end (or its API clients) sends, in a browser's order and with
// a browser's headers. Every request is one a user of the application
// sends: the denials of a policy on this traffic are its false positives.
// The applications (-app), each in its own file:
//
//   - juice-shop: OWASP Juice Shop, an online shop with an Angular front
//     end and a REST API (juiceshop.go).
//   - gitea: Gitea, a code forge: its web UI and its REST API, with
//     Markdown issues and comments, code and attachments (gitea.go).
//   - wordpress: WordPress, a CMS: its admin, the block editor's REST
//     calls, media uploads, comments and searches (wordpress.go).
//   - directus: Directus, a headless CMS's JSON API: REST with JSON
//     filters, GraphQL, file uploads (directus.go).
//
// It records the requests only, with the response's status: no response
// body (the application's content) is in the file, and the address it was
// sent to is replaced by -public-url everywhere in the requests. Free text
// (reviews, posts, issues, searches) is drawn from fixed lists with a fixed
// seed, so a recording against the same version has the same requests,
// apart from IDs, nonces and tokens the application hands out. Passwords
// are the made-up users' own; sessions and tokens are the throwaway ones
// of the recording's container.
//
//	docker run --rm -d -p 3000:3000 bkimminich/juice-shop:<JUICE_SHOP_VERSION>
//	go run ./hack/fptraffic -app juice-shop -target http://127.0.0.1:3000 -out hack/fptraffic/juice-shop.har.gz
//
// make fp-har runs both (hack/fptraffic/record.sh, APP=<app>), with the
// versions in hack/versions.env, on a new application.
package main

import (
	"bytes"
	"cmp"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	picture "image"
	"image/color"
	"image/png"
	"io"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// app is an application fptraffic plays.
type app struct {
	// about is the HAR's comment; public, the origin written into it.
	about, public string
	// sessions: the users played, one session each.
	sessions int
	// jar: the session keeps the cookies the application sets.
	jar bool
	// setup, if set, prepares the application (an install), unrecorded.
	setup func(r *recorder)
	// session plays user n.
	session func(r *recorder, n int)
}

var apps = map[string]app{
	"juice-shop": juiceShop,
	"gitea":      giteaApp,
	"wordpress":  wordpress,
	"directus":   directus,
}

func main() {
	name := flag.String("app", "juice-shop", "the application: juice-shop, gitea, wordpress or directus")
	target := flag.String("target", "http://127.0.0.1:3000", "the application to send the requests to")
	public := flag.String("public-url", "", "the origin written into the HAR (URLs, Origin, Referer) instead of -target's (default: the application's)")
	out := flag.String("out", "", "HAR file to write, gzip-compressed if its name ends with .gz (default <app>.har.gz)")
	sessions := flag.Int("sessions", 0, "users to play, one session each (default: the application's)")
	seed := flag.Uint64("seed", 600, "seed of the choices (texts, browsers)")
	flag.Parse()
	a, ok := apps[*name]
	if !ok {
		fail(fmt.Errorf("-app %q: want juice-shop, gitea, wordpress or directus", *name))
	}
	if *public == "" {
		*public = a.public
	}
	if *out == "" {
		*out = *name + ".har.gz"
	}
	if *sessions == 0 {
		*sessions = a.sessions
	}
	r, err := newRecorder(*target, *public, *seed)
	if err != nil {
		fail(err)
	}
	if err := r.play(a, *sessions); err != nil {
		fail(err)
	}
	b, err := json.MarshalIndent(r.har, "", "  ")
	if err != nil {
		fail(err)
	}
	b = append(b, '\n')
	// A .gz name: compressed, as the repository keeps it (2 MB of JSON,
	// mostly the applications' tokens, in 50 KB).
	if strings.HasSuffix(*out, ".gz") {
		var z bytes.Buffer
		zw, err := gzip.NewWriterLevel(&z, gzip.BestCompression)
		if err != nil {
			fail(err)
		}
		if _, err := zw.Write(b); err != nil {
			fail(err)
		}
		if err := zw.Close(); err != nil {
			fail(err)
		}
		b = z.Bytes()
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil { //nolint:gosec // a file of the repository, read by everyone
		fail(err)
	}
	fmt.Printf("%d requests from %d sessions in %s\n", len(r.har.Log.Entries), *sessions, *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fptraffic:", err)
	os.Exit(1)
}

// play runs the application's setup, unrecorded, then its sessions.
func (r *recorder) play(a app, sessions int) error {
	r.har.Log.Creator.Comment = a.about + ": requests only, each with its response's status"
	r.jar = a.jar
	if a.setup != nil {
		r.quiet = true
		err := r.run(func() { a.setup(r) })
		r.quiet = false
		if err != nil {
			return fmt.Errorf("setup: %w", err)
		}
	}
	for i := range sessions {
		r.ua = browsers[i%len(browsers)]
		r.cookies, r.token, r.referer, r.cached = nil, "", "", map[string]bool{}
		if err := r.run(func() { a.session(r, i) }); err != nil {
			return fmt.Errorf("session %d: %w", i+1, err)
		}
	}
	return nil
}

// run runs f, a session's steps, which panic with a sessionError on a
// failed request.
func (r *recorder) run(f func()) (err error) {
	defer func() {
		if p := recover(); p != nil {
			se, ok := p.(sessionError)
			if !ok {
				panic(p)
			}
			err = se.error
		}
	}()
	f()
	return nil
}

// The HAR 1.2 subset written: what inkwallctl test --har reads, and what a
// HAR viewer needs to open the file.
type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
}

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Cookies     []harNV      `json:"cookies"`
	Headers     []harNV      `json:"headers"`
	QueryString []harNV      `json:"queryString"`
	PostData    *harPostData `json:"postData,omitempty"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int          `json:"bodySize"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []harNV    `json:"cookies"`
	Headers     []harNV    `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Comment  string `json:"comment,omitempty"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// recorder sends requests to the application and records them.
type recorder struct {
	target, public string
	client         *http.Client
	rnd            *rand.Rand
	har            harFile
	// toPublic replaces the target's origin with the public one in what is
	// recorded: applications put their own URLs in forms and posts.
	toPublic *strings.Replacer
	// quiet: requests are sent, not recorded (an application's setup).
	quiet bool
	// jar: the cookies the application sets are kept.
	jar bool
	// The session's browser and state.
	ua      browser
	cookies []harNV
	// token, if set, goes in the Authorization header of API calls, after
	// scheme (Bearer if empty).
	token, scheme string
	// The page's URL: the shop routes in its fragment (#/search), which
	// browsers leave out of Referer.
	referer string
	// cached: the assets the browser has, fetched once a session.
	cached map[string]bool
}

func newRecorder(target, public string, seed uint64) (*recorder, error) {
	for _, u := range []string{target, public} {
		if p, err := url.Parse(u); err != nil || p.Host == "" {
			return nil, fmt.Errorf("%q: want an absolute URL", u)
		}
	}
	r := &recorder{
		target: strings.TrimSuffix(target, "/"),
		public: strings.TrimSuffix(public, "/"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			// The recorded requests are the ones sent: no redirect followed
			// behind the recorder's back.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			// Accept-Encoding is set (and recorded) like a browser's, so the
			// transport doesn't add its own.
			Transport: &http.Transport{DisableCompression: true},
		},
		rnd:    rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), //nolint:gosec // seeded on purpose: the same choices each time
		cached: map[string]bool{},
	}
	t, p := r.target, r.public
	r.toPublic = strings.NewReplacer(t, p, url.QueryEscape(t), url.QueryEscape(p), strings.ReplaceAll(t, "/", `\/`), strings.ReplaceAll(p, "/", `\/`))
	r.har.Log = harLog{Version: "1.2", Creator: harCreator{Name: "inkwall hack/fptraffic", Version: "1"}}
	return r, nil
}

// browser is a client's identity: the headers every request of its
// session carries.
type browser struct {
	userAgent, language string
	// chromium: the client hints Chrome and Edge send.
	chromium bool
	hints    string
	platform string
}

var browsers = []browser{
	{userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
		language: "en-US,en;q=0.9", chromium: true, hints: `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`, platform: `"Windows"`},
	{userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
		language: "en-GB,en;q=0.9"},
	{userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
		language: "de-DE,de;q=0.8,en-US;q=0.5,en;q=0.3"},
	{userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
		language: "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", chromium: true, hints: `"Microsoft Edge";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`, platform: `"Windows"`},
	{userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
		language: "es-ES,es;q=0.9"},
	{userAgent: "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
		language: "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7", chromium: true, hints: `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`, platform: `"Android"`},
}

// kind is what a request is for, which sets its Accept and Sec-Fetch-*
// headers as a browser does.
type kind int

const (
	document kind = iota
	script
	style
	image
	font
	api
	// client: a program's API call (a CLI, a script, a service), with
	// the headers of that program, not a browser's.
	client
)

type request struct {
	kind   kind
	method string
	path   string
	// One of: body (with contentType), or form (multipart).
	contentType string
	body        []byte
	// headers: more headers, sent and recorded after the others (a CSRF
	// token, a nonce).
	headers []harNV
}

// with returns q with a header more.
func (q request) with(name, value string) request {
	q.headers = append(slices.Clip(q.headers), harNV{Name: name, Value: value})
	return q
}

// as returns q as another kind of request.
func (q request) as(k kind) request {
	q.kind = k
	return q
}

// response is what a session needs of an answer.
type response struct {
	status   int
	body     []byte
	location string
}

// json decodes the body into v, if it is JSON.
func (resp response) json(v any) bool {
	return json.Unmarshal(resp.body, v) == nil
}

func (r *recorder) do(q request) (response, error) {
	h := http.Header{}
	h.Set("User-Agent", r.ua.userAgent)
	h.Set("Accept-Language", r.ua.language)
	h.Set("Accept-Encoding", "gzip, deflate")
	dest, mode := "empty", "cors"
	if q.kind == client {
		h = http.Header{}
		h.Set("User-Agent", r.ua.userAgent)
		h.Set("Accept", "application/json")
		h.Set("Accept-Encoding", "gzip")
	}
	switch q.kind {
	case document:
		h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		h.Set("Upgrade-Insecure-Requests", "1")
		dest, mode = "document", "navigate"
	case script:
		h.Set("Accept", "*/*")
		dest = "script"
	case style:
		h.Set("Accept", "text/css,*/*;q=0.1")
		dest, mode = "style", "no-cors"
	case image:
		h.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
		dest, mode = "image", "no-cors"
	case font:
		h.Set("Accept", "*/*")
		dest = "font"
	case api, client:
		if q.kind == api {
			h.Set("Accept", "application/json, text/plain, */*")
		}
		if r.token != "" {
			h.Set("Authorization", cmp.Or(r.scheme, "Bearer")+" "+r.token)
		}
	}
	if q.kind != client {
		if r.ua.chromium {
			h.Set("Sec-Ch-Ua", r.ua.hints)
			h.Set("Sec-Ch-Ua-Mobile", map[bool]string{true: "?1", false: "?0"}[strings.Contains(r.ua.userAgent, "Mobile")])
			h.Set("Sec-Ch-Ua-Platform", r.ua.platform)
		}
		h.Set("Sec-Fetch-Dest", dest)
		h.Set("Sec-Fetch-Mode", mode)
		h.Set("Sec-Fetch-Site", "same-origin")
		if r.referer != "" {
			h.Set("Referer", r.referer)
		}
		if q.method != http.MethodGet && q.method != http.MethodHead {
			h.Set("Origin", r.public)
		}
	}
	if q.contentType != "" {
		h.Set("Content-Type", q.contentType)
	}
	if len(r.cookies) > 0 {
		parts := make([]string, len(r.cookies))
		for i, c := range r.cookies {
			parts[i] = c.Name + "=" + c.Value
		}
		h.Set("Cookie", strings.Join(parts, "; "))
	}

	req, err := http.NewRequest(q.method, r.target+q.path, bytes.NewReader(q.body))
	if err != nil {
		return response{}, err
	}
	req.Header = h
	for _, nv := range q.headers {
		req.Header.Set(nv.Name, nv.Value)
	}
	if q.body == nil {
		req.Body, req.ContentLength = http.NoBody, 0
	}
	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		return response{}, err
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return response{}, err
	}
	elapsed := time.Since(start)
	body := decode(resp.Header.Get("Content-Encoding"), raw)
	if r.jar {
		for _, c := range resp.Cookies() {
			if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
				r.dropCookie(c.Name)
			} else {
				r.setCookie(c.Name, c.Value)
			}
		}
	}
	// The redirect, as a path of the target if it is one.
	location := resp.Header.Get("Location")
	if base, err := url.Parse(r.target + q.path); err == nil && location != "" {
		if to, err := base.Parse(location); err == nil && to.Host == base.Host {
			location = to.RequestURI()
		}
	}
	if r.quiet {
		return response{status: resp.StatusCode, body: body, location: location}, nil
	}

	// What is recorded: the public origin for the target's.
	var sent []byte
	if q.body != nil {
		sent = []byte(r.toPublic.Replace(string(q.body)))
	}
	for name, vs := range h {
		h[name] = []string{r.toPublic.Replace(vs[0])}
	}
	u, err := url.Parse(r.public + r.toPublic.Replace(q.path))
	if err != nil {
		return response{}, err
	}
	entry := harEntry{
		StartedDateTime: start.UTC().Format(time.RFC3339Nano),
		Time:            ms(elapsed),
		Request: harRequest{
			Method: q.method, URL: u.String(), HTTPVersion: "HTTP/1.1",
			// The cookies are in the Cookie header: not repeated here.
			Cookies: []harNV{}, Headers: []harNV{{Name: "Host", Value: u.Host}},
			QueryString: []harNV{}, HeadersSize: -1, BodySize: len(sent),
		},
		Response: harResponse{
			Status: resp.StatusCode, StatusText: http.StatusText(resp.StatusCode), HTTPVersion: "HTTP/1.1",
			Cookies: []harNV{}, Headers: []harNV{},
			Content:     harContent{Size: len(body), MimeType: resp.Header.Get("Content-Type"), Comment: "not recorded"},
			RedirectURL: r.toPublic.Replace(resp.Header.Get("Location")), HeadersSize: -1, BodySize: -1,
		},
		Timings: harTimings{Wait: ms(elapsed)},
	}
	if sent != nil {
		entry.Request.Headers = append(entry.Request.Headers, harNV{Name: "Content-Length", Value: fmt.Sprint(len(sent))})
	}
	for _, name := range headerOrder {
		if v := h.Get(name); v != "" {
			entry.Request.Headers = append(entry.Request.Headers, harNV{Name: name, Value: v})
		}
	}
	for _, nv := range q.headers {
		entry.Request.Headers = append(entry.Request.Headers, harNV{Name: nv.Name, Value: r.toPublic.Replace(nv.Value)})
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			entry.Request.QueryString = append(entry.Request.QueryString, harNV{Name: k, Value: v})
		}
	}
	if sent != nil {
		entry.Request.PostData = &harPostData{MimeType: q.contentType, Text: string(sent)}
		// A binary body (an image upload) as base64, which HAR readers
		// decode, so its bytes are the ones sent.
		if !utf8.Valid(sent) {
			entry.Request.PostData.Text, entry.Request.PostData.Encoding = base64.StdEncoding.EncodeToString(sent), "base64"
		}
	}
	r.har.Log.Entries = append(r.har.Log.Entries, entry)
	if q.kind == document {
		r.referer = u.String()
	}
	return response{status: resp.StatusCode, body: body, location: location}, nil
}

// headerOrder is the order of the recorded headers, as a browser sends
// them (Go's header map has none).
var headerOrder = []string{
	"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "Authorization",
	"User-Agent", "Content-Type", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
	"Referer", "Accept-Encoding", "Accept-Language", "Cookie",
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func decode(encoding string, b []byte) []byte {
	var rd io.Reader
	switch strings.ToLower(encoding) {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return b
		}
		rd = zr
	case "deflate":
		rd = flate.NewReader(bytes.NewReader(b))
	default:
		return b
	}
	out, err := io.ReadAll(rd)
	if err != nil {
		return b
	}
	return out
}

func jsonBody(method, path string, v any) request {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return request{kind: api, method: method, path: path, contentType: "application/json", body: b}
}

func get(k kind, path string) request { return request{kind: k, method: http.MethodGet, path: path} }

func (r *recorder) pick(list []string) string { return list[r.rnd.IntN(len(list))] }

func (r *recorder) setCookie(name, value string) {
	for i, c := range r.cookies {
		if c.Name == name {
			r.cookies[i].Value = value
			return
		}
	}
	r.cookies = append(r.cookies, harNV{Name: name, Value: value})
}

func (r *recorder) dropCookie(name string) {
	r.cookies = slices.DeleteFunc(r.cookies, func(c harNV) bool { return c.Name == name })
}

// must sends q and fails on a transport error; a status the application
// answers is recorded whatever it is.
func (r *recorder) must(q request) response {
	resp, err := r.do(q)
	if err != nil {
		panic(sessionError{err})
	}
	return resp
}

type sessionError struct{ error }

// multipartBody is a form a browser uploads: fields, then one file.
func multipartBody(path string, fields map[string]string, fileField, fileName, fileType, content string) request {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// A boundary like a browser's, fixed for a stable file.
	if err := w.SetBoundary("----WebKitFormBoundary7MA4YWxkTrZu0gW"); err != nil {
		panic(err)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err := w.WriteField(k, fields[k]); err != nil {
			panic(err)
		}
	}
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, fileField, fileName))
	h.Set("Content-Type", fileType)
	part, err := w.CreatePart(h)
	if err != nil {
		panic(err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return request{kind: api, method: http.MethodPost, path: path, contentType: w.FormDataContentType(), body: b.Bytes()}
}

// formBody is a form a browser submits (application/x-www-form-urlencoded),
// its fields in the page's order: name, value, name, value...
func formBody(path string, fields ...string) request {
	parts := make([]string, 0, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		parts = append(parts, url.QueryEscape(fields[i])+"="+url.QueryEscape(fields[i+1]))
	}
	if len(parts) == 0 {
		return request{kind: document, method: http.MethodPost, path: path}
	}
	return request{kind: document, method: http.MethodPost, path: path,
		contentType: "application/x-www-form-urlencoded", body: []byte(strings.Join(parts, "&"))}
}

// pageAssetRE finds the scripts, stylesheets, images and fonts a page
// names.
var pageAssetRE = regexp.MustCompile(`(?:src|href)=["']([^"'#]+?\.(?:js|css|ico|svg|png|woff2?)(?:\?[^"']*)?)["']`)

// page loads a page as a browser does: the document, then the assets it
// names that the browser doesn't have yet (of the same origin; at most
// 20).
func (r *recorder) page(path string) response {
	resp := r.must(get(document, path))
	n := 0
	for _, m := range pageAssetRE.FindAllStringSubmatch(string(resp.body), -1) {
		p := strings.ReplaceAll(m[1], "&#038;", "&")
		p = strings.ReplaceAll(p, "&amp;", "&")
		if rest, ok := strings.CutPrefix(p, r.target); ok {
			p = rest
		}
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || r.cached[p] || n == 20 {
			continue
		}
		r.cached[p] = true
		n++
		file, _, _ := strings.Cut(p, "?")
		k := image
		switch {
		case strings.HasSuffix(file, ".js"):
			k = script
		case strings.HasSuffix(file, ".css"):
			k = style
		case strings.HasSuffix(file, ".woff"), strings.HasSuffix(file, ".woff2"):
			k = font
		}
		r.must(get(k, p))
	}
	return resp
}

// follow loads the page a form's answer redirects to, if it does.
func (r *recorder) follow(resp response) response {
	if resp.status/100 != 3 || resp.location == "" || strings.Contains(resp.location, "://") {
		return resp
	}
	return r.page(resp.location)
}

// samplePNG is the image users upload (a photo, an avatar, a cover): a
// 16x16 gradient, a PNG image libraries decode and resize.
var samplePNG = func() string {
	img := picture.NewRGBA(picture.Rect(0, 0, 16, 16))
	for x := range 16 {
		for y := range 16 {
			img.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 16), B: 128, A: 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		panic(err)
	}
	return b.String()
}()

// find returns the first group of re in b, or "".
func find(b []byte, re *regexp.Regexp) string {
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}
