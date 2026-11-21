// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// wordpress is WordPress (https://wordpress.org, GPLv2), a CMS: server
// pages for the admin and the readers, and the REST API its block editor
// calls. The administrator logs in, sets the permalinks and the site's
// title, adds the authors and the categories; each author saves a quick
// draft, writes a post in the block editor (blocks of HTML: links,
// lists, quotes, code, an uploaded image with its caption), tags and
// publishes it; readers browse, search and comment; the administrator
// approves and answers the comments. Everyone logs out. The setup (the
// installation) isn't recorded.
var wordpress = app{
	about:    "WordPress's traffic (its admin, block editor and site), played by hack/fptraffic",
	public:   "https://blog.example.com",
	sessions: 8,
	jar:      true,
	setup:    (*recorder).wpInstall,
	session:  (*recorder).wpSession,
}

type wpUser struct {
	login, email, password, first, last, url string
}

var wpAdmin = wpUser{"siobhan", "siobhan.oconnor@example.com", "Gr33n-Fields!2026", "Siobhán", "O'Connor", "https://siobhan.example.com"}

var wpAuthors = []wpUser{
	{"jlefevre", "jl.lefevre+blog@example.org", "C'est-la-vie_99", "Jean-Luc", "Lefèvre", "https://lefevre.example.org/"},
	{"anna.ms", "anna.mueller@example.de", "Sommer#Regen&Wind", "Anna", "Müller-Schmidt", ""},
	{"dangelo", "dangelo.smith@example.net", "P@ssw0rd; it's long", "D'Angelo", "Smith Jr.", "https://dangelo.example.net"},
	{"mjgarcia", "mj_garcia@example.es", "contraseña<segura>1", "María José", "García-López", ""},
}

// wpReaders comment as guests: name, email, website.
var wpReaders = [][3]string{
	{"Zoë Ng", "zoe.ng@example.co.uk", ""},
	{"Tomás O'Reilly", "tomas@example.ie", "https://tomas.example.ie/about?lang=en&ref=blog"},
	{"李明", "liming@example.cn", ""},
	{"Fatima Al-Hassan", "fatima.alhassan@example.com", "https://example.com/~fatima"},
}

type wpPost struct {
	title, excerpt string
	// content: the blocks, with %[1]s for the uploaded image's URL and
	// %[2]d for its ID.
	content            string
	category, tag, alt string
}

var wpPosts = []wpPost{
	{"Ratatouille : la recette de ma grand-mère", "Une recette simple, d'été, pour 4 personnes.",
		`<!-- wp:paragraph -->
<p>La ratatouille, c'est <strong>l'été dans une casserole</strong>. Ma grand-mère la faisait « à la niçoise » ; voici sa version, notée sur un carnet de 1972.</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":%[2]d,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="%[1]s" alt="Une ratatouille dans une cocotte en fonte" class="wp-image-%[2]d"/><figcaption class="wp-element-caption">La cocotte de mamie (photo : J.-L. L.)</figcaption></figure>
<!-- /wp:image -->

<!-- wp:heading -->
<h2 class="wp-block-heading">Ingrédients (4 pers.)</h2>
<!-- /wp:heading -->

<!-- wp:list -->
<ul class="wp-block-list"><!-- wp:list-item -->
<li>2 aubergines &amp; 3 courgettes</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>1 poivron rouge, 1 jaune</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>4 tomates, 2 oignons, 3 gousses d'ail</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>Huile d'olive, thym, laurier — sel &amp; poivre</li>
<!-- /wp:list-item --></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p>Cuire chaque légume <em>séparément</em> (c'est le secret !), puis tout réunir 30 min à feu doux. Voir aussi <a href="https://example.org/recettes?cat=provence&amp;page=2">d'autres recettes provençales</a>.</p>
<!-- /wp:paragraph -->`,
		"Recettes", "cuisine provençale", "Une ratatouille dans une cocotte en fonte"},
	{"Barrierefreie Formulare: 5 Tipps", "Was wir beim Relaunch unserer Formulare gelernt haben.",
		`<!-- wp:paragraph -->
<p>Formulare sind für viele Nutzer:innen die größte Hürde. Hier sind fünf Dinge, die wir beim Relaunch gelernt haben.</p>
<!-- /wp:paragraph -->

<!-- wp:list {"ordered":true} -->
<ol class="wp-block-list"><!-- wp:list-item -->
<li>Jedes Feld braucht ein <code>&lt;label for="…"&gt;</code>, kein Platzhalter als Ersatz.</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>Fehler <strong>beim Feld</strong> anzeigen, mit <code>aria-describedby</code>.</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>Keine Zeitlimits (oder: verlängerbar).</li>
<!-- /wp:list-item --></ol>
<!-- /wp:list -->

<!-- wp:code -->
<pre class="wp-block-code"><code>&lt;label for="email"&gt;E-Mail-Adresse&lt;/label&gt;
&lt;input id="email" type="email" autocomplete="email" aria-describedby="email-hint"&gt;
&lt;p id="email-hint"&gt;Wir schicken Ihnen nur die Bestellbestätigung.&lt;/p&gt;</code></pre>
<!-- /wp:code -->

<!-- wp:image {"id":%[2]d,"sizeSlug":"medium"} -->
<figure class="wp-block-image size-medium"><img src="%[1]s" alt="Screenshot des neuen Kontaktformulars" class="wp-image-%[2]d"/></figure>
<!-- /wp:image -->`,
		"Technik", "Barrierefreiheit", "Screenshot des neuen Kontaktformulars"},
	{"Postmortem: the 40-minute outage on Nov 3rd", "What happened, why, and what we're changing.",
		`<!-- wp:paragraph -->
<p><strong>TL;DR:</strong> a config change set the DB pool to 0; checkout returned 500s for 40 minutes (14:02–14:42 UTC). No data was lost.</p>
<!-- /wp:paragraph -->

<!-- wp:heading -->
<h2 class="wp-block-heading">Timeline</h2>
<!-- /wp:heading -->

<!-- wp:table -->
<figure class="wp-block-table"><table><thead><tr><th>Time (UTC)</th><th>Event</th></tr></thead><tbody><tr><td>14:02</td><td>Deploy of <code>config-2026-11-03.1</code></td></tr><tr><td>14:09</td><td>Alert: 5xx rate &gt; 5%</td></tr><tr><td>14:42</td><td>Rollback; error rate back to &lt; 0.1%</td></tr></tbody></table></figure>
<!-- /wp:table -->

<!-- wp:paragraph -->
<p>The change looked harmless in review:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>- max_connections: ${DB_POOL_SIZE:-20}
+ max_connections: ${DB_POOL:-0}</code></pre>
<!-- /wp:code -->

<!-- wp:quote -->
<blockquote class="wp-block-quote"><!-- wp:paragraph -->
<p>"Defaults that fail closed are only safe if someone notices them." — our on-call, at 14:30</p>
<!-- /wp:paragraph --></blockquote>
<!-- /wp:quote -->

<!-- wp:image {"id":%[2]d} -->
<figure class="wp-block-image"><img src="%[1]s" alt="Graph of the error rate during the outage" class="wp-image-%[2]d"/><figcaption class="wp-element-caption">Error rate, 13:30–15:00</figcaption></figure>
<!-- /wp:image -->`,
		"Engineering", "postmortem", "Graph of the error rate during the outage"},
	{"Guía rápida: cómo elegir tus primeras botas de montaña", "Consejos para principiantes, sin gastar una fortuna.",
		`<!-- wp:paragraph -->
<p>¿Vas a empezar a hacer senderismo? Lo más importante son las botas. Aquí van mis consejos tras 10 años (y 6 pares) en los Picos de Europa.</p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul class="wp-block-list"><!-- wp:list-item -->
<li>Pruébalas <em>por la tarde</em>, con el calcetín que vas a usar.</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>Deja 1 cm delante del dedo gordo (¡bajando se nota!).</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>Presupuesto: 90–150 € está bien para empezar.</li>
<!-- /wp:list-item --></ul>
<!-- /wp:list -->

<!-- wp:image {"id":%[2]d,"sizeSlug":"large"} -->
<figure class="wp-block-image size-large"><img src="%[1]s" alt="Botas de montaña sobre una roca" class="wp-image-%[2]d"/><figcaption class="wp-element-caption">Mis botas en el Naranjo de Bulnes</figcaption></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Más info en la <a href="https://example.es/guia?tema=botas&amp;nivel=principiante#tallas">guía de tallas</a>.</p>
<!-- /wp:paragraph -->`,
		"Viajes", "senderismo", "Botas de montaña sobre una roca"},
}

var wpDrafts = []struct{ title, content string }{
	{"Idées pour la semaine", "Soupe au pistou, tarte tatin… et peut-être un article sur le café ?"},
	{"Notizen: Kontrast & Fokus", "Kontrastverhältnis mindestens 4.5:1; Fokus-Ring nie mit outline: none entfernen!"},
	{"TODO before Friday", "1) finish the postmortem 2) ask Anna about the forms 3) <3 coffee"},
	{"Ideas", "Rutas: Somiedo (fácil), Ordesa (media) & Aneto (difícil)."},
}

var wpComments = []string{
	"Merci pour la recette ! J'ai ajouté une pincée de piment d'Espelette, c'était parfait.",
	"Great write-up. We had almost the same incident last year -- \"fail closed\" defaults are sneaky. Did you add a test for the config?",
	"很好的文章，谢谢分享！",
	"Danke für die Tipps! Eine Frage: wie geht ihr mit <select>-Feldern um, die sehr lange Listen haben?",
	"I'd add one thing: break them in *before* the trip :) Mine gave me blisters on day 1...",
	"Is the 1 cm rule for every brand? My size is 42 in one & 43 in another.",
}

var wpReplies = []string{
	"Thanks for reading! Yes, there's now a check in CI that fails on a pool size of 0.",
	"Gracias, Fatima. Depende de la marca, sí: pruébalas siempre.",
}

var wpSearches = []string{"ratatouille", "outage", "botas de montaña", "formulare", "café", "post-mortem 2026", "O'Connor", "tips & tricks"}

var (
	wpRestNonce  = regexp.MustCompile(`createNonceMiddleware\( "([0-9a-f]+)" \)`)
	wpHeartbeat  = regexp.MustCompile(`heartbeatSettings = \{"nonce":"([0-9a-f]+)"`)
	wpEditorPost = regexp.MustCompile(`initializeEditor\( 'editor', "post", ([0-9]+)`)
	wpLogout     = regexp.MustCompile(`action=logout&(?:amp;|#038;)?_wpnonce=([0-9a-f]+)`)
	wpNonce      = regexp.MustCompile(`name="_wpnonce" value="([0-9a-f]+)"`)
	wpCreateUser = regexp.MustCompile(`name="_wpnonce_create-user" value="([0-9a-f]+)"`)
	wpQuickPost  = regexp.MustCompile(`name="post_ID" value="([0-9]+)"`)
	wpReplyNonce = regexp.MustCompile(`name="_ajax_nonce-replyto-comment" value="([0-9a-f]+)"`)
	wpApprove    = regexp.MustCompile(`action=approvecomment&(?:amp;|#038;)?c=([0-9]+)&(?:amp;|#038;)?_wpnonce=([0-9a-f]+)`)
)

// wpInstall installs WordPress, as its first page asks.
func (r *recorder) wpInstall() {
	r.must(get(document, "/wp-admin/install.php?step=1"))
	r.must(formBody("/wp-admin/install.php?step=2", "weblog_title", "Notes & Recipes", "user_name", wpAdmin.login,
		"admin_password", wpAdmin.password, "admin_password2", wpAdmin.password, "pw_weak", "on",
		"admin_email", wpAdmin.email, "blog_public", "0", "language", ""))
}

func (r *recorder) wpSession(n int) {
	switch {
	case n == 0:
		r.wpAdminSetup()
	case n <= len(wpAuthors):
		r.wpAuthor(n - 1)
	case n == 7:
		r.wpModerate()
	default:
		r.wpReader(n)
	}
}

// wpLogin logs in through the login form, and returns the dashboard.
func (r *recorder) wpLogin(u wpUser) response {
	r.page("/wp-login.php")
	resp := r.must(formBody("/wp-login.php", "log", u.login, "pwd", u.password, "rememberme", "forever",
		"wp-submit", "Log In", "redirect_to", r.target+"/wp-admin/", "testcookie", "1"))
	if resp.status != http.StatusFound {
		panic(sessionError{fmt.Errorf("login as %s: status %d", u.login, resp.status)})
	}
	dash := r.follow(resp)
	r.wpHeartbeat(dash, "dashboard")
	return dash
}

// wpHeartbeat is the admin's periodic call.
func (r *recorder) wpHeartbeat(page response, screen string) {
	if nonce := find(page.body, wpHeartbeat); nonce != "" {
		r.must(formBody("/wp-admin/admin-ajax.php", "interval", "60", "_nonce", nonce, "action", "heartbeat",
			"screen_id", screen, "has_focus", "false").as(api))
	}
}

func (r *recorder) wpLogout(page response) {
	if nonce := find(page.body, wpLogout); nonce != "" {
		r.follow(r.must(get(document, "/wp-login.php?action=logout&_wpnonce="+nonce)))
	}
}

// wpREST is a call of the block editor: the REST API, with the nonce.
func wpREST(method, path, nonce string, v any) request {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	q := get(api, "/wp-json"+path+sep+"_locale=user")
	if v != nil {
		q = jsonBody(http.MethodPost, q.path, v)
		// apiFetch sends PUT and DELETE as POST, with the method in a
		// header.
		if method != http.MethodPost {
			q = q.with("X-HTTP-Method-Override", method)
		}
	}
	return q.with("X-WP-Nonce", nonce)
}

func (r *recorder) wpAdminSetup() {
	dash := r.wpLogin(wpAdmin)
	// Permalinks: /%postname%/, which turns on /wp-json/.
	page := r.page("/wp-admin/options-permalink.php")
	r.follow(r.must(formBody("/wp-admin/options-permalink.php", "_wpnonce", find(page.body, wpNonce),
		"_wp_http_referer", "/wp-admin/options-permalink.php", "selection", "/%postname%/", "permalink_structure", "/%postname%/",
		"category_base", "", "tag_base", "", "submit", "Save Changes")))
	page = r.page("/wp-admin/options-general.php")
	r.follow(r.must(formBody("/wp-admin/options.php", "option_page", "general", "action", "update",
		"_wpnonce", find(page.body, wpNonce), "_wp_http_referer", "/wp-admin/options-general.php",
		"blogname", "Notes & Recipes", "blogdescription", "Siobhán's team blog: food, code & mountains",
		"siteurl", r.target, "home", r.target, "new_admin_email", wpAdmin.email, "default_role", "subscriber",
		"WPLANG", "", "timezone_string", "Europe/Dublin", "date_format", "j F Y", "date_format_custom", "j F Y",
		"time_format", "H:i", "time_format_custom", "H:i", "start_of_week", "1", "submit", "Save Changes")))
	for _, a := range wpAuthors {
		page := r.page("/wp-admin/user-new.php")
		r.follow(r.must(formBody("/wp-admin/user-new.php", "action", "createuser", "_wpnonce_create-user", find(page.body, wpCreateUser),
			"_wp_http_referer", "/wp-admin/user-new.php", "user_login", a.login, "email", a.email,
			"first_name", a.first, "last_name", a.last, "url", a.url, "pass1", a.password, "pass2", a.password,
			"pw_weak", "on", "role", "author", "createuser", "Add User")))
	}
	page = r.page("/wp-admin/post-new.php")
	nonce := find(page.body, wpRestNonce)
	for _, c := range []map[string]any{
		{"name": "Recettes", "description": "Cuisine de tous les jours"},
		{"name": "Technik", "description": "Web, Formulare & Barrierefreiheit"},
		{"name": "Engineering", "description": "Postmortems, how-tos and other war stories"},
		{"name": "Viajes", "description": "Montaña, rutas y equipo"},
	} {
		r.must(wpREST(http.MethodPost, "/wp/v2/categories", nonce, c))
	}
	r.wpLogout(dash)
}

func (r *recorder) wpAuthor(i int) {
	u, post, draft := wpAuthors[i], wpPosts[i%len(wpPosts)], wpDrafts[i%len(wpDrafts)]
	dash := r.wpLogin(u)
	// A quick draft, from the dashboard.
	r.must(formBody("/wp-admin/post.php", "post_title", draft.title, "content", draft.content,
		"action", "post-quickdraft-save", "post_ID", find(dash.body, wpQuickPost), "_wpnonce", find(dash.body, wpNonce),
		"_wp_http_referer", "/wp-admin/", "save", "Save Draft").as(api))

	// A post, in the block editor.
	editor := r.page("/wp-admin/post-new.php")
	nonce, id := find(editor.body, wpRestNonce), find(editor.body, wpEditorPost)
	r.wpHeartbeat(editor, "post")
	r.must(wpREST(http.MethodGet, "/wp/v2/users/me?context=edit", nonce, nil))
	r.must(wpREST(http.MethodGet, "/wp/v2/categories?context=view&per_page=100&_fields=id%2Cname%2Cparent", nonce, nil))
	r.must(wpREST(http.MethodPut, "/wp/v2/posts/"+id, nonce, map[string]any{"id": id, "title": post.title, "status": "draft"}))
	upload := multipartBody("/wp-json/wp/v2/media?_locale=user", map[string]string{"post": id}, "file",
		strings.ToLower(strings.ReplaceAll(post.tag, " ", "-"))+".png", "image/png", samplePNG).with("X-WP-Nonce", nonce)
	var media struct {
		ID        int    `json:"id"`
		SourceURL string `json:"source_url"`
	}
	r.must(upload).json(&media)
	r.must(wpREST(http.MethodPut, fmt.Sprintf("/wp/v2/media/%d", media.ID), nonce, map[string]any{
		"id": media.ID, "alt_text": post.alt, "caption": post.alt + " (" + u.first + ")",
	}))
	content := fmt.Sprintf(post.content, media.SourceURL, media.ID)
	r.must(wpREST(http.MethodPost, "/wp/v2/posts/"+id+"/autosaves", nonce, map[string]any{
		"id": id, "title": post.title, "content": content, "excerpt": post.excerpt,
	}))
	r.must(wpREST(http.MethodGet, "/wp/v2/tags?search="+url.QueryEscape(strings.Fields(post.tag)[0])+"&per_page=20&context=view", nonce, nil))
	var tag struct {
		ID int `json:"id"`
	}
	r.must(wpREST(http.MethodPost, "/wp/v2/tags", nonce, map[string]any{"name": post.tag})).json(&tag)
	var cats []struct {
		ID int `json:"id"`
	}
	r.must(wpREST(http.MethodGet, "/wp/v2/categories?search="+url.QueryEscape(post.category)+"&context=view", nonce, nil)).json(&cats)
	catIDs := []int{}
	for _, c := range cats {
		catIDs = append(catIDs, c.ID)
	}
	r.must(wpREST(http.MethodGet, "/wp/v2/search?search="+url.QueryEscape(r.pick(wpSearches))+"&per_page=20&type=post", nonce, nil))
	var published struct {
		Link string `json:"link"`
	}
	r.must(wpREST(http.MethodPut, "/wp/v2/posts/"+id, nonce, map[string]any{
		"id": id, "title": post.title, "content": content, "excerpt": post.excerpt, "status": "publish",
		"categories": catIDs, "tags": []int{tag.ID}, "featured_media": media.ID, "comment_status": "open",
	})).json(&published)
	r.must(wpREST(http.MethodGet, "/wp/v2/posts/"+id+"?context=edit", nonce, nil))
	if link := strings.TrimPrefix(published.Link, r.target); strings.HasPrefix(link, "/") {
		r.page(link)
	}
	r.page("/wp-admin/edit.php")
	r.page("/wp-admin/edit.php?s=" + url.QueryEscape(r.pick(wpSearches)) + "&post_status=all&post_type=post")
	r.wpLogout(dash)
}

func (r *recorder) wpReader(n int) {
	r.page("/")
	r.page("/?s=" + url.QueryEscape(r.pick(wpSearches)))
	var posts []struct {
		ID   int    `json:"id"`
		Link string `json:"link"`
	}
	r.must(get(api, "/wp-json/wp/v2/posts?per_page=10&_fields=id,link,title")).json(&posts)
	for k := range 2 {
		if len(posts) == 0 {
			break
		}
		p := posts[(n+k)%len(posts)]
		link := strings.TrimPrefix(p.Link, r.target)
		r.page(link)
		who := wpReaders[(n*2+k)%len(wpReaders)]
		r.follow(r.must(formBody("/wp-comments-post.php", "comment", wpComments[(n*2+k)%len(wpComments)],
			"author", who[0], "email", who[1], "url", who[2], "wp-comment-cookies-consent", "yes",
			"submit", "Post Comment", "comment_post_ID", fmt.Sprint(p.ID), "comment_parent", "0")))
	}
	r.page("/category/engineering/")
	r.must(get(document, "/feed/"))
	r.must(get(api, "/wp-json/wp/v2/search?search="+url.QueryEscape(r.pick(wpSearches))+"&per_page=5"))
	r.page("/?s=" + url.QueryEscape(r.pick(wpSearches)) + "&post_type=post")
}

func (r *recorder) wpModerate() {
	dash := r.wpLogin(wpAdmin)
	nonce := find(r.page("/wp-admin/post-new.php").body, wpRestNonce)
	var held []struct {
		ID   int `json:"id"`
		Post int `json:"post"`
	}
	r.must(wpREST(http.MethodGet, "/wp/v2/comments?per_page=20&status=hold&context=edit", nonce, nil)).json(&held)
	posts := map[string]string{}
	for _, c := range held {
		posts[fmt.Sprint(c.ID)] = fmt.Sprint(c.Post)
	}
	page := r.page("/wp-admin/edit-comments.php?comment_status=moderated")
	reply := find(page.body, wpReplyNonce)
	for i, m := range wpApprove.FindAllSubmatch(page.body, -1) {
		id, dim := string(m[1]), string(m[2])
		r.must(formBody("/wp-admin/admin-ajax.php", "id", id, "new", "approved", "_ajax_nonce", dim,
			"action", "dim-comment", "_total", fmt.Sprint(len(held)), "_per_page", "20", "_page", "1",
			"_url", r.target+"/wp-admin/edit-comments.php?comment_status=moderated").as(api))
		if i < len(wpReplies) {
			r.must(formBody("/wp-admin/admin-ajax.php", "_ajax_nonce-replyto-comment", reply, "action", "replyto-comment",
				"comment_ID", id, "comment_post_ID", posts[id], "status", "", "position", "-1", "checkbox", "1", "mode", "detail",
				"content", wpReplies[i]).as(api))
		}
	}
	r.page("/wp-admin/edit-comments.php")
	r.wpLogout(dash)
}
