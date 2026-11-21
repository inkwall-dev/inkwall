// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// juiceShop is OWASP Juice Shop (https://github.com/juice-shop/juice-shop,
// MIT), an online shop with an Angular front end and a REST API. Each
// shopper loads the pages and assets, registers, answers a security
// question, logs in, searches, reads and writes product reviews, fills and
// changes a basket, adds an address and a card, checks out, tracks the
// order, sends feedback through the captcha, uploads a complaint and a
// photo, changes their password and exports their data.
var juiceShop = app{
	about:    "OWASP Juice Shop's traffic, played by hack/fptraffic",
	public:   "https://shop.example.com",
	sessions: 6,
	session:  (*recorder).shopper,
}

// shopper plays one shopper, from the landing page to the logout.
func (r *recorder) shopper(n int) {
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
