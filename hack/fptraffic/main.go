// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command fptraffic records the traffic of a real application as a HAR
// file, for the false-positive run (hack/fp-run.sh, make fp-run; #600).
// The application is OWASP Juice Shop (https://github.com/juice-shop/juice-shop,
// MIT), an online shop with an Angular front end and a REST API: fptraffic
// plays a few shoppers, each with the requests the shop's front end sends,
// in a browser's order and with a browser's headers. They load the pages
// and assets, register, answer a security question, log in, search, read
// and write product reviews, fill and change a basket, add an address and
// a card, check out, track the order, send feedback through the captcha,
// ask the chat bot, upload a complaint and a photo, change their password
// and export their data. Every request is one a user of the shop sends:
// the denials of a policy on this traffic are its false positives.
//
// It records the requests only, with the response's status: no response
// body (the shop's content) is in the file. Free text (reviews, feedback,
// searches, chat) is drawn from the lists below with a fixed seed, so a
// recording against the same Juice Shop version has the same requests,
// apart from IDs and tokens the shop hands out.
//
//	docker run --rm -d -p 3000:3000 bkimminich/juice-shop:<JUICE_SHOP_VERSION>
//	go run ./hack/fptraffic -target http://127.0.0.1:3000 -out hack/fptraffic/juice-shop.har.gz
//
// make fp-har runs both (hack/fptraffic/record.sh), with the version in
// hack/versions.env, on a new shop.
package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
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
)

func main() {
	target := flag.String("target", "http://127.0.0.1:3000", "the Juice Shop to send the requests to")
	public := flag.String("public-url", "https://shop.example.com", "the origin written into the HAR (URLs, Origin, Referer) instead of -target's")
	out := flag.String("out", "juice-shop.har.gz", "HAR file to write (gzip-compressed if its name ends with .gz)")
	shoppers := flag.Int("shoppers", 6, "shoppers to play, one session each")
	seed := flag.Uint64("seed", 600, "seed of the choices (products, texts, browsers)")
	flag.Parse()
	r, err := newRecorder(*target, *public, *seed)
	if err != nil {
		fail(err)
	}
	for i := range *shoppers {
		if err := r.session(i); err != nil {
			fail(fmt.Errorf("shopper %d: %w", i+1, err))
		}
	}
	b, err := json.MarshalIndent(r.har, "", "  ")
	if err != nil {
		fail(err)
	}
	b = append(b, '\n')
	// A .gz name: compressed, as the repository keeps it (2 MB of JSON,
	// mostly the shop's tokens, in 50 KB).
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
	fmt.Printf("%d requests from %d shoppers in %s\n", len(r.har.Log.Entries), *shoppers, *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fptraffic:", err)
	os.Exit(1)
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

// recorder sends requests to the shop and records them.
type recorder struct {
	target, public string
	client         *http.Client
	rnd            *rand.Rand
	har            harFile
	// The session's browser and state.
	ua      browser
	cookies []harNV
	token   string
	// The page's URL: the shop routes in its fragment (#/search), which
	// browsers leave out of Referer.
	referer string
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
		rnd: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), //nolint:gosec // seeded on purpose: the same choices each time
	}
	r.har.Log = harLog{Version: "1.2", Creator: harCreator{
		Name: "inkwall hack/fptraffic", Version: "1",
		Comment: "OWASP Juice Shop's traffic, played by hack/fptraffic: requests only, each with its response's status",
	}}
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
)

type request struct {
	kind   kind
	method string
	path   string
	// One of: body (with contentType), or form (multipart).
	contentType string
	body        []byte
}

// response is what a session needs of an answer.
type response struct {
	status int
	body   []byte
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
	case api:
		h.Set("Accept", "application/json, text/plain, */*")
		if r.token != "" {
			h.Set("Authorization", "Bearer "+r.token)
		}
	}
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

	u, err := url.Parse(r.public + q.path)
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
			QueryString: []harNV{}, HeadersSize: -1, BodySize: len(q.body),
		},
		Response: harResponse{
			Status: resp.StatusCode, StatusText: http.StatusText(resp.StatusCode), HTTPVersion: "HTTP/1.1",
			Cookies: []harNV{}, Headers: []harNV{},
			Content:     harContent{Size: len(body), MimeType: resp.Header.Get("Content-Type"), Comment: "not recorded"},
			RedirectURL: resp.Header.Get("Location"), HeadersSize: -1, BodySize: -1,
		},
		Timings: harTimings{Wait: ms(elapsed)},
	}
	if q.body != nil {
		entry.Request.Headers = append(entry.Request.Headers, harNV{Name: "Content-Length", Value: fmt.Sprint(len(q.body))})
	}
	for _, name := range headerOrder {
		if v := h.Get(name); v != "" {
			entry.Request.Headers = append(entry.Request.Headers, harNV{Name: name, Value: v})
		}
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			entry.Request.QueryString = append(entry.Request.QueryString, harNV{Name: k, Value: v})
		}
	}
	if q.body != nil {
		entry.Request.PostData = &harPostData{MimeType: q.contentType, Text: string(q.body)}
	}
	r.har.Log.Entries = append(r.har.Log.Entries, entry)
	if q.kind == document {
		r.referer = u.String()
	}
	return response{status: resp.StatusCode, body: body}, nil
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

// must sends q and fails on a transport error; a status the shop answers
// is recorded whatever it is.
func (r *recorder) must(q request) response {
	resp, err := r.do(q)
	if err != nil {
		panic(sessionError{err})
	}
	return resp
}

type sessionError struct{ error }

// session plays one shopper, from the landing page to the logout.
func (r *recorder) session(n int) (err error) {
	defer func() {
		if p := recover(); p != nil {
			se, ok := p.(sessionError)
			if !ok {
				panic(p)
			}
			err = se.error
		}
	}()
	r.ua = browsers[n%len(browsers)]
	r.cookies, r.token, r.referer = nil, "", ""

	u := shoppers[n%len(shoppers)]
	r.landing()
	r.register(u)
	basket := r.login(u)
	r.browse(u)
	r.fillBasket(basket)
	addressID := r.address(u)
	cardID := r.card(u)
	r.checkout(basket, addressID, cardID)
	r.feedback(n)
	r.complaint(n)
	r.memory(u)
	r.account(u)
	r.must(get(api, "/rest/products/search?q="))
	r.logout()
	return nil
}

var assetRE = regexp.MustCompile(`(?:src|href)="([^"]+\.(?:js|css|ico))"`)

// landing loads the shop: the document, the assets it names, and the
// front end's first API calls.
func (r *recorder) landing() {
	page := r.must(get(document, "/"))
	for _, m := range assetRE.FindAllStringSubmatch(string(page.body), -1) {
		p := m[1]
		if strings.Contains(p, "://") {
			continue
		}
		k := script
		switch {
		case strings.HasSuffix(p, ".css"):
			k = style
		case strings.HasSuffix(p, ".ico"):
			k = image
		}
		r.must(get(k, "/"+strings.TrimPrefix(p, "/")))
	}
	r.must(get(font, "/assets/public/MaterialIcons-Regular.woff2"))
	r.must(get(api, "/rest/admin/application-configuration"))
	r.must(get(api, "/assets/i18n/"+i18nFile(r.ua.language)))
	r.must(get(api, "/rest/admin/application-version"))
	r.must(get(api, "/rest/languages"))
	r.must(get(api, "/api/Challenges/?name=Score%20Board"))
	r.must(get(api, "/rest/products/search?q="))
	r.must(get(api, "/api/Quantitys/"))
	r.must(get(image, "/assets/public/images/JuiceShop_Logo.png"))
	for range 6 {
		r.must(get(image, "/assets/public/images/products/"+r.pick(productImages)))
	}
	r.setCookie("language", strings.TrimSuffix(i18nFile(r.ua.language), ".json"))
	r.setCookie("welcomebanner_status", "dismiss")
	r.setCookie("cookieconsent_status", "dismiss")
	r.must(get(api, "/socket.io/?EIO=4&transport=polling&t="+pollToken(r.rnd)))
}

// i18nFile is the shop's translation file for the browser's first
// language: en.json, de_DE.json, ...
func i18nFile(lang string) string {
	tag := strings.SplitN(lang, ",", 2)[0]
	l, reg, _ := strings.Cut(tag, "-")
	if l == "en" {
		return "en.json"
	}
	return l + "_" + strings.ToUpper(reg) + ".json"
}

// pollToken is the t parameter Socket.IO's polling transport adds.
func pollToken(rnd *rand.Rand) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
	b := make([]byte, 7)
	for i := range b {
		b[i] = alphabet[rnd.IntN(len(alphabet))]
	}
	return string(b)
}

type shopper struct {
	name, email, password, answer     string
	question                          int
	street, city, state, zip, country string
	mobile                            int64
	card                              int64
}

// Made-up shoppers, with what makes real names, passwords and addresses
// hard for a WAF: apostrophes, hyphens, accents, symbols.
var shoppers = []shopper{
	{"Siobhán O'Connor", "siobhan.oconnor@example.com", "Gr33n-Fields!2026", "O'Brien", 2,
		"12 St. Stephen's Green", "Dublin", "Leinster", "D02 XY45", "Ireland", 871234567, 4111111111111111},
	{"Jean-Luc Lefèvre", "jl.lefevre+shop@example.org", "C'est-la-vie_99", "Lyon", 6,
		"8, rue de l'Église", "Paris", "Île-de-France", "75004", "France", 612345678, 5555555555554444},
	{"Anna Müller-Schmidt", "anna.mueller@example.de", "Sommer#Regen&Wind", "Max", 1,
		"Hauptstraße 5/7", "München", "Bayern", "80331", "Germany", 1511234567, 4012888888881881},
	{"D'Angelo Smith Jr.", "dangelo.smith@example.net", "P@ssw0rd; it's long", "Rover (our dog)", 3,
		"1600 Pennsylvania Ave. NW, Apt #4", "Washington", "D.C.", "20500", "United States", 2025550143, 4242424242424242},
	{"María José García-López", "mj_garcia@example.es", "contraseña<segura>1", "Pérez", 2,
		"Calle de Alcalá, 42 - 3º B", "Madrid", "Comunidad de Madrid", "28014", "Spain", 612345678, 6011111111111117},
	{"Zoë Ng", "zoe.ng@example.co.uk", "select the best one", "1984", 7,
		"Flat 2, 10 Baker Street", "London", "Greater London", "NW1 6XE", "United Kingdom", 7700900123, 4000056655665556},
}

var productImages = []string{
	"apple_juice.jpg", "apple_pressings.jpg", "banana_juice.jpg", "carrot_juice.jpeg", "eggfruit_juice.jpg",
	"fruit_press.jpg", "green_smoothie.jpg", "lemon_juice.jpg", "melon_bike.jpeg", "permafrost.jpg",
	"sticker.png", "fan_shop.jpg", "artwork2.jpg", "thingie1.jpg", "undefined.png",
}

// Searches as people type them.
var searches = []string{
	"apple", "banana juice", "lemon", "smoothie", "orange & lemon", "100% juice", "o'reilly", "sticker",
	"t-shirt size L", "fruit press", "Don't stop", "melon bike", "kids", "\"green smoothie\"", "juice < 5 euro",
	"eggfruit", "carrot (organic)", "hoodie", "1+1", "cool stuff", "jus d'orange", "Apfelsaft 1,5l",
}

// Reviews, feedback and complaints: free text as people write it.
var reviews = []string{
	"Tastes great, my kids love it! Will buy again.",
	"Not bad, but a bit too sweet for my taste. 3/5",
	"I've tried every juice here & this one's the best :-)",
	"Arrived quickly; packaging was OK. The bottle's cap was a little loose though.",
	"Best purchase ever!!! <3",
	"Ordered 2, got 1... customer service sorted it out within a day. Thanks!",
	"Is it really 100% fruit? The label says \"from concentrate\" -- a bit misleading.",
	"Works as advertised. Select the larger size, it's better value.",
	"Meh. My wife liked it, I didn't. Your mileage may vary.",
	"Five stars: fresh, cold, and the delivery guy was friendly.",
	"Would be nice to have a sugar-free option (or one with less than 5g/100ml).",
	"C'est délicieux ! Livraison rapide, merci.",
	"Sehr lecker, aber etwas teuer für 0,5 l.",
	"The sticker peeled off after one week in the dishwasher; expected that, still cute.",
	"Bought this for a party -- everyone asked where it's from. Union of taste & health!",
	"Price/quality: 4 out of 5. I'd drop a star for the plastic bottle.",
}

var complaints = []string{
	"My order arrived with a broken bottle; see the attached receipt.",
	"I was charged twice for order #4471 -- please refund one of them.",
	"The delivery was left at the wrong address (No. 12 instead of No. 21).",
}

var memoryCaptions = []string{
	"Sunday brunch with the new smoothie :)", "Our team's juice-tasting day!", "Me & my bike, fuelled by melon juice",
}

var securityQuestions = []string{
	"", "Your eldest siblings middle name?", "Mother's maiden name?", "Mother's birth date? (MM/DD/YY)",
	"Father's birth date? (MM/DD/YY)", "Maternal grandmother's first name?", "Paternal grandmother's first name?",
	"Name of your favorite pet?",
}

func (r *recorder) register(u shopper) {
	r.must(get(api, "/api/SecurityQuestions/"))
	resp := r.must(jsonBody(http.MethodPost, "/api/Users/", map[string]any{
		"email": u.email, "password": u.password, "passwordRepeat": u.password,
		"securityQuestion": map[string]any{"id": u.question, "question": securityQuestions[u.question],
			"createdAt": "2026-11-14T08:00:00.000Z", "updatedAt": "2026-11-14T08:00:00.000Z"},
		"securityAnswer": u.answer,
	}))
	var created struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if resp.json(&created) && created.Data.ID != 0 {
		r.must(jsonBody(http.MethodPost, "/api/SecurityAnswers/", map[string]any{
			"UserId": created.Data.ID, "answer": u.answer, "SecurityQuestionId": u.question,
		}))
	}
}

// login returns the shopper's basket.
func (r *recorder) login(u shopper) int {
	resp := r.must(jsonBody(http.MethodPost, "/rest/user/login", map[string]any{"email": u.email, "password": u.password}))
	var auth struct {
		Authentication struct {
			Token string `json:"token"`
			Bid   int    `json:"bid"`
		} `json:"authentication"`
	}
	if !resp.json(&auth) || auth.Authentication.Token == "" {
		panic(sessionError{fmt.Errorf("login as %s: status %d, no token", u.email, resp.status)})
	}
	r.token = auth.Authentication.Token
	r.setCookie("token", r.token)
	r.must(get(api, "/rest/user/whoami"))
	r.must(get(api, "/rest/saveLoginIp"))
	r.must(get(api, "/rest/products/search?q="))
	r.must(get(api, fmt.Sprintf("/rest/basket/%d", auth.Authentication.Bid)))
	return auth.Authentication.Bid
}

func (r *recorder) browse(u shopper) {
	for range 4 {
		q := r.pick(searches)
		r.must(get(api, "/rest/products/search?q="+url.QueryEscape(q)))
	}
	for range 3 {
		id := 1 + r.rnd.IntN(24)
		r.must(get(api, fmt.Sprintf("/rest/products/%d/reviews", id)))
		if r.rnd.IntN(2) == 0 {
			r.must(jsonBody(http.MethodPut, fmt.Sprintf("/rest/products/%d/reviews", id), map[string]any{
				"message": r.pick(reviews), "author": u.email,
			}))
			r.must(get(api, fmt.Sprintf("/rest/products/%d/reviews", id)))
		}
	}
	r.must(get(api, "/api/Feedbacks/"))
	r.must(get(api, "/redirect?to=https://github.com/juice-shop/juice-shop"))
}

func (r *recorder) fillBasket(basket int) {
	var items []int
	// Three products, each once: the shop refuses a product already in the
	// basket (its front end adds to the quantity instead).
	for _, p := range r.rnd.Perm(12)[:3] {
		resp := r.must(jsonBody(http.MethodPost, "/api/BasketItems/", map[string]any{
			"ProductId": 1 + p, "BasketId": fmt.Sprint(basket), "quantity": 1,
		}))
		var item struct {
			Data struct {
				ID int `json:"id"`
			} `json:"data"`
		}
		if resp.json(&item) && item.Data.ID != 0 {
			items = append(items, item.Data.ID)
		}
		r.must(get(api, fmt.Sprintf("/rest/basket/%d", basket)))
	}
	r.must(get(api, fmt.Sprintf("/rest/basket/%d", basket)))
	if len(items) > 0 {
		r.must(get(api, fmt.Sprintf("/api/BasketItems/%d", items[0])))
		r.must(jsonBody(http.MethodPut, fmt.Sprintf("/api/BasketItems/%d", items[0]), map[string]any{"quantity": 2}))
	}
	if len(items) > 2 {
		r.must(request{kind: api, method: http.MethodDelete, path: fmt.Sprintf("/api/BasketItems/%d", items[2])})
	}
	r.must(get(api, fmt.Sprintf("/rest/basket/%d", basket)))
}

func (r *recorder) address(u shopper) int {
	r.must(get(api, "/api/Addresss"))
	resp := r.must(jsonBody(http.MethodPost, "/api/Addresss/", map[string]any{
		"country": u.country, "fullName": u.name, "mobileNum": u.mobile, "zipCode": u.zip,
		"streetAddress": u.street, "city": u.city, "state": u.state,
	}))
	r.must(get(api, "/api/Addresss"))
	return dataID(resp)
}

func (r *recorder) card(u shopper) int {
	r.must(get(api, "/api/Deliverys")) //nolint:misspell // the shop's path
	r.must(get(api, "/rest/wallet/balance"))
	r.must(get(api, "/api/Cards"))
	resp := r.must(jsonBody(http.MethodPost, "/api/Cards/", map[string]any{
		"fullName": u.name, "cardNum": u.card, "expMonth": fmt.Sprint(1 + r.rnd.IntN(12)), "expYear": fmt.Sprint(2080 + r.rnd.IntN(19)),
	}))
	r.must(get(api, "/api/Cards"))
	return dataID(resp)
}

func dataID(resp response) int {
	var v struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	resp.json(&v)
	return v.Data.ID
}

func (r *recorder) checkout(basket, addressID, cardID int) {
	r.must(get(api, fmt.Sprintf("/rest/basket/%d", basket)))
	r.must(get(api, fmt.Sprintf("/api/Addresss/%d", addressID)))
	r.must(get(api, "/api/Deliverys/1")) //nolint:misspell // the shop's path
	resp := r.must(jsonBody(http.MethodPost, fmt.Sprintf("/rest/basket/%d/checkout", basket), map[string]any{
		"couponData": "bnVsbA==",
		"orderDetails": map[string]any{
			"paymentId": fmt.Sprint(cardID), "addressId": fmt.Sprint(addressID), "deliveryMethodId": "1",
		},
	}))
	var order struct {
		OrderConfirmation string `json:"orderConfirmation"`
	}
	if resp.json(&order) && order.OrderConfirmation != "" {
		r.must(get(api, "/rest/track-order/"+order.OrderConfirmation))
		r.must(get(api, "/rest/basket/"+fmt.Sprint(basket)))
		r.must(get(api, "/rest/order-history"))
	}
}

func (r *recorder) feedback(n int) {
	who := r.must(get(api, "/rest/user/whoami"))
	var u struct {
		User struct {
			ID    int    `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	who.json(&u)
	resp := r.must(get(api, "/rest/captcha/"))
	var c struct {
		CaptchaID int    `json:"captchaId"`
		Answer    string `json:"answer"`
	}
	resp.json(&c)
	// The front end masks the author's email in the comment.
	masked := "anonymous"
	if at := strings.IndexByte(u.User.Email, '@'); at > 0 {
		masked = "***" + u.User.Email[at-1:]
	}
	r.must(jsonBody(http.MethodPost, "/api/Feedbacks/", map[string]any{
		"UserId": u.User.ID, "captchaId": c.CaptchaID, "captcha": c.Answer,
		"comment": reviews[(n*5+3)%len(reviews)] + " (" + masked + ")", "rating": 1 + (n*3)%5,
	}))
}

func (r *recorder) complaint(n int) {
	r.must(get(api, "/rest/user/whoami"))
	name := fmt.Sprintf("receipt-%d.pdf", 1000+n)
	pdf := "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n" +
		"trailer << /Root 1 0 R >>\n%%EOF\n"
	r.must(multipartBody("/file-upload", nil, "file", name, "application/pdf", pdf))
	who := r.must(get(api, "/rest/user/whoami"))
	var u struct {
		User struct {
			ID int `json:"id"`
		} `json:"user"`
	}
	who.json(&u)
	r.must(jsonBody(http.MethodPost, "/api/Complaints/", map[string]any{
		"UserId": u.User.ID, "message": complaints[n%len(complaints)], "file": name,
	}))
}

func (r *recorder) memory(u shopper) {
	r.must(get(api, "/rest/memories"))
	// A 1x1 PNG.
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89" +
		"\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7\x35\x81\x84\x00\x00\x00\x00IEND\xaeB`\x82"
	r.must(multipartBody("/rest/memories", map[string]string{"caption": r.pick(memoryCaptions)}, "image",
		strings.ToLower(strings.Fields(u.name)[0])+"-brunch.png", "image/png", png))
	r.must(get(api, "/rest/memories"))
}

func (r *recorder) account(u shopper) {
	q := url.Values{"current": {u.password}, "new": {u.password + "!"}, "repeat": {u.password + "!"}}
	r.must(get(api, "/rest/user/change-password?"+q.Encode()))
	r.must(get(api, "/rest/2fa/status"))
	r.must(get(api, "/rest/image-captcha/"))
	r.must(jsonBody(http.MethodPost, "/rest/user/data-export", map[string]any{"format": "1", "answer": fmt.Sprint(10000 + r.rnd.IntN(90000))}))
	r.must(get(api, "/rest/deluxe-membership"))
	r.must(get(api, "/rest/wallet/balance"))
	r.must(get(api, "/api/Recycles"))
	r.must(get(api, "/api/Quantitys/"))
}

// logout drops the token, as the front end does; it tells the server
// nothing.
func (r *recorder) logout() {
	r.token = ""
	kept := r.cookies[:0]
	for _, c := range r.cookies {
		if c.Name != "token" {
			kept = append(kept, c)
		}
	}
	r.cookies = kept
	r.must(get(api, "/rest/admin/application-configuration"))
}

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
