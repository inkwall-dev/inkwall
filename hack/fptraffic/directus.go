// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// directus is Directus (https://directus.io, BSL 1.1, free for small
// organizations), a headless CMS: a JSON REST API with filters, sorts and
// field lists in the query string (JSON or bracket syntax), a GraphQL API,
// and file uploads, called by its own Vue app (the Data Studio) and by
// services with a static token. The administrator's script models the
// content (collections and fields), makes a role with its policy and
// permissions, the editors and a service account. Each editor logs in to
// the Data Studio (session cookie), lists, searches and filters articles
// and customers, creates and edits them (Markdown and HTML bodies, JSON
// fields), uploads a cover image, runs aggregates, queries GraphQL, and
// logs out. The service imports customers in a batch and reads through
// GraphQL and REST.
var directus = app{
	about:    "Directus's traffic (its REST and GraphQL APIs, from its Data Studio and a service), played by hack/fptraffic",
	public:   "https://cms.example.com",
	sessions: 6,
	jar:      true,
	session:  (*recorder).dxSession,
}

type dxUser struct{ email, password, first, last, title, lang string }

var dxAdmin = dxUser{"siobhan.oconnor@example.com", "Gr33n-Fields!2026", "Siobhán", "O'Connor", "Head of Content", "en-US"}

var dxEditors = []dxUser{
	{"jl.lefevre+cms@example.org", "C'est-la-vie_99", "Jean-Luc", "Lefèvre", "Rédacteur en chef", "fr-FR"},
	{"anna.mueller@example.de", "Sommer#Regen&Wind", "Anna", "Müller-Schmidt", "Redakteurin", "de-DE"},
	{"dangelo.smith@example.net", "P@ssw0rd; it's long", "D'Angelo", "Smith Jr.", "Editor (Tech)", "en-US"},
	{"mj_garcia@example.es", "contraseña<segura>1", "María José", "García-López", "Editora", "es-ES"},
}

// The service account's static token: a throwaway value of the recording.
const dxServiceToken = "fp-run-service-token-6f1c2a9e" //nolint:gosec // a throwaway token of the recording's container

type dxArticle struct {
	title, summary, body string
	tags                 []string
	rating               float64
}

var dxArticles = []dxArticle{
	{"Les 10 meilleurs cafés de Lyon", "Notre sélection 2026, du croissant au flat white.",
		"## Pourquoi cette liste ?\n\nOn a testé **42 cafés** en 3 mois. Critères : le café (évidemment), l'accueil & le calme.\n\n1. *La Tasse* — 12, rue de l'Arbre-Sec\n2. *Chez Mémé* — quai Saint-Antoine\n\n> « Le meilleur expresso de la presqu'île. » — un lecteur\n\nVoir la [carte](https://maps.example.org/?q=cafés+lyon&z=14).",
		[]string{"café", "Lyon", "guide"}, 4.5},
	{"Release notes 3.2: dark mode & faster search", "Dark mode, a 3x faster search and 14 bug fixes.",
		"<h2>What's new</h2><p>Dark mode is here! Toggle it in <em>Settings → Appearance</em>.</p><ul><li>Search is ~3× faster (p95 &lt; 120 ms)</li><li>Exports support <code>.csv</code> &amp; <code>.xlsx</code></li></ul><p>Upgrade with <code>npm install @example/app@3.2.0</code>.</p>",
		[]string{"release", "changelog"}, 5},
	{"Wie wir unsere Datenbank migriert haben", "Von MySQL 5.7 zu PostgreSQL 17, ohne Downtime.",
		"## Ausgangslage\n\n- 1,2 TB Daten, 340 Tabellen\n- Spitzenlast: 8.000 Anfragen/s\n\n```sql\nSELECT table_name, pg_size_pretty(pg_total_relation_size(quote_ident(table_name)))\nFROM information_schema.tables\nWHERE table_schema = 'public'\nORDER BY 2 DESC LIMIT 10;\n```\n\nDas Wichtigste: *Dual Writes* für zwei Wochen, dann Umschalten per Feature-Flag.",
		[]string{"PostgreSQL", "Migration"}, 4},
	{"Cómo escribir un buen README", "Plantilla y consejos para proyectos de código abierto.",
		"Un buen README responde a 3 preguntas: ¿qué es?, ¿cómo lo instalo? y ¿cómo contribuyo?\n\n```bash\ngit clone https://example.com/proyecto.git && cd proyecto\nmake install\n```\n\n¡No olvides la licencia (MIT, Apache-2.0, GPL-3.0…)!",
		[]string{"documentación", "open source"}, 4.8},
}

var dxCustomers = []map[string]any{
	{"name": "Siobhán O'Connor", "email": "siobhan.oconnor@example.com", "country": "Ireland", "notes": "Prefers e-mail; VIP since 2019.",
		"address": map[string]any{"street": "12 St. Stephen's Green", "city": "Dublin", "zip": "D02 XY45"}},
	{"name": "Jean-Luc Lefèvre", "email": "jl.lefevre@example.org", "country": "France", "notes": "Facture au nom de « Lefèvre & Fils SARL ».",
		"address": map[string]any{"street": "8, rue de l'Église", "city": "Paris", "zip": "75004"}},
	{"name": "Anna Müller-Schmidt", "email": "anna.mueller@example.de", "country": "Germany", "notes": "Rückruf nur zwischen 9–12 Uhr.",
		"address": map[string]any{"street": "Hauptstraße 5/7", "city": "München", "zip": "80331"}},
	{"name": "D'Angelo Smith Jr.", "email": "dangelo.smith@example.net", "country": "United States", "notes": "Account #4471 -- duplicate of #4470? Check before merging.",
		"address": map[string]any{"street": "1600 Pennsylvania Ave. NW, Apt #4", "city": "Washington", "zip": "20500"}},
	{"name": "María José García-López", "email": "mj_garcia@example.es", "country": "Spain", "notes": "Cliente desde 2021; descuento del 10 %.",
		"address": map[string]any{"street": "Calle de Alcalá, 42 - 3º B", "city": "Madrid", "zip": "28014"}},
	{"name": "Zoë Ng", "email": "zoe.ng@example.co.uk", "country": "United Kingdom", "notes": "Select the annual plan at renewal (asked on the phone).",
		"address": map[string]any{"street": "Flat 2, 10 Baker Street", "city": "London", "zip": "NW1 6XE"}},
}

var dxSearches = []string{"café", "release 3.2", "PostgreSQL", "README", "O'Connor", "Müller", "dark mode", "10 %"}

func (r *recorder) dxSession(n int) {
	switch {
	case n == 0:
		r.dxModel()
	case n <= len(dxEditors):
		r.dxEditor(n - 1)
	default:
		r.dxService()
	}
}

// dxModel is the administrator's script: the content model, the editors'
// role and the users.
func (r *recorder) dxModel() {
	r.ua.userAgent = "python-requests/2.32.5"
	var auth struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	r.must(jsonBody(http.MethodPost, "/auth/login", map[string]any{"email": dxAdmin.email, "password": dxAdmin.password}).as(client)).json(&auth)
	if auth.Data.AccessToken == "" {
		panic(sessionError{fmt.Errorf("directus: the administrator's login failed")})
	}
	r.token = auth.Data.AccessToken
	r.must(get(client, "/server/info"))
	r.must(get(client, "/collections?limit=-1"))
	pk := map[string]any{"field": "id", "type": "integer", "meta": map[string]any{"hidden": true, "interface": "input", "readonly": true},
		"schema": map[string]any{"is_primary_key": true, "has_auto_increment": true}}
	field := func(name, typ, iface string, special ...string) map[string]any {
		meta := map[string]any{"interface": iface}
		if len(special) > 0 {
			meta["special"] = special
		}
		return map[string]any{"field": name, "type": typ, "meta": meta, "schema": map[string]any{}}
	}
	r.must(jsonBody(http.MethodPost, "/collections", map[string]any{
		"collection": "articles", "meta": map[string]any{"icon": "article", "note": "Blog posts & news (Markdown or HTML)", "sort_field": "sort"},
		"schema": map[string]any{},
		"fields": []any{pk,
			field("status", "string", "select-dropdown"), field("title", "string", "input"), field("summary", "text", "input-multiline"),
			field("body", "text", "input-rich-text-md"), field("tags", "json", "tags", "cast-json"), field("metadata", "json", "input-code", "cast-json"),
			field("rating", "float", "input"), field("published_at", "timestamp", "datetime"), field("cover", "uuid", "file-image", "file"),
			field("sort", "integer", "input"),
			field("user_created", "uuid", "select-dropdown-m2o", "user-created"), field("date_created", "timestamp", "datetime", "date-created"),
		},
	}).as(client))
	r.must(jsonBody(http.MethodPost, "/collections", map[string]any{
		"collection": "customers", "meta": map[string]any{"icon": "person", "note": "CRM: one row per customer"},
		"schema": map[string]any{},
		"fields": []any{pk,
			field("name", "string", "input"), field("email", "string", "input"), field("country", "string", "select-dropdown"),
			field("notes", "text", "input-multiline"), field("address", "json", "input-code", "cast-json"),
		},
	}).as(client))
	r.must(jsonBody(http.MethodPost, "/relations", map[string]any{
		"collection": "articles", "field": "cover", "related_collection": "directus_files",
		"schema": map[string]any{"on_delete": "SET NULL"},
	}).as(client))

	// Two roles, each with its policy and permissions: the editors, who
	// use the Data Studio, and the writers, whose front end and services
	// use the API only (the free edition counts only the Studio's seats).
	roles := map[bool]any{}
	for _, studio := range []bool{true, false} {
		name := map[bool]string{true: "Editor", false: "Writer"}[studio]
		policy := r.dxID(r.must(jsonBody(http.MethodPost, "/policies", map[string]any{
			"name": name + "s", "icon": "edit", "description": "Write & publish articles; manage customers", "app_access": studio, "admin_access": false,
		}).as(client)))
		var perms []map[string]any
		for _, c := range []string{"articles", "customers", "directus_files"} {
			for _, a := range []string{"create", "read", "update", "delete"} {
				perms = append(perms, map[string]any{"policy": policy, "collection": c, "action": a, "fields": []string{"*"}, "permissions": map[string]any{}})
			}
		}
		for _, c := range []string{"directus_revisions", "directus_activity"} {
			perms = append(perms, map[string]any{"policy": policy, "collection": c, "action": "read", "fields": []string{"*"}, "permissions": map[string]any{}})
		}
		r.must(jsonBody(http.MethodPost, "/permissions", perms).as(client))
		roles[studio] = r.dxID(r.must(jsonBody(http.MethodPost, "/roles", map[string]any{
			"name": name, "icon": "supervised_user_circle", "description": "Content team (FR/DE/ES/EN)",
			"policies": map[string]any{"create": []any{map[string]any{"policy": policy}}, "update": []any{}, "delete": []any{}},
		}).as(client)))
	}
	for i, e := range dxEditors {
		r.must(jsonBody(http.MethodPost, "/users", map[string]any{
			"email": e.email, "password": e.password, "first_name": e.first, "last_name": e.last, "title": e.title,
			"language": e.lang, "role": roles[dxStudio(i)], "status": "active",
		}).as(client))
	}
	r.must(jsonBody(http.MethodPost, "/users", map[string]any{
		"email": "importer@example.com", "first_name": "CRM", "last_name": "Importer (bot)", "role": roles[false],
		"token": dxServiceToken, "status": "active", "description": "Nightly import from the CRM; owner: Siobhán",
	}).as(client))
	r.must(get(client, "/users?fields=id,email,role.name&filter="+url.QueryEscape(`{"role":{"name":{"_in":["Editor","Writer"]}}}`)))
}

// dxID is the id of the object Directus answers with.
func (r *recorder) dxID(resp response) any {
	var v struct {
		Data struct {
			ID any `json:"id"`
		} `json:"data"`
	}
	resp.json(&v)
	return v.Data.ID
}

func (r *recorder) dxEditor(i int) {
	u := dxEditors[i]
	a := dxArticles[i%len(dxArticles)]
	studio := dxStudio(i)
	var refresh string
	if studio {
		// The Data Studio: a session cookie.
		r.page("/admin/login")
		r.must(jsonBody(http.MethodPost, "/auth/login", map[string]any{"email": u.email, "password": u.password, "mode": "session"}))
		for _, p := range []string{
			"/server/info", "/users/me?fields=*&fields=role.*&fields=avatar.id", "/settings?fields=*", "/collections?limit=-1",
			"/fields?limit=-1", "/relations?limit=-1", "/permissions/me", "/presets?limit=-1&filter=" + url.QueryEscape(`{"_or":[{"user":{"_eq":"$CURRENT_USER"}},{"user":{"_null":true}}]}`),
		} {
			r.must(get(api, p))
		}
	} else {
		// The team's own front end: tokens, in JSON.
		var auth struct {
			Data struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"data"`
		}
		r.must(jsonBody(http.MethodPost, "/auth/login", map[string]any{"email": u.email, "password": u.password})).json(&auth)
		r.token, refresh = auth.Data.AccessToken, auth.Data.RefreshToken
		r.must(get(api, "/server/info"))
		r.must(get(api, "/users/me?fields=id,first_name,last_name,language,role.name"))
	}
	// The articles: the list, a search, a filter.
	list := "/items/articles?limit=25&fields[]=id&fields[]=title&fields[]=status&fields[]=user_created.first_name&sort[]=-date_created&page=1"
	r.must(get(api, list))
	r.must(get(api, "/items/articles?aggregate[count]=*&meta=filter_count"))
	r.must(get(api, list+"&search="+url.QueryEscape(r.pick(dxSearches))))
	r.must(get(api, list+"&filter="+url.QueryEscape(`{"_and":[{"status":{"_eq":"published"}},{"title":{"_icontains":"`+strings.Fields(a.title)[1]+`"}}]}`)))
	id := r.dxID(r.must(jsonBody(http.MethodPost, "/items/articles", map[string]any{
		"status": "draft", "title": a.title, "summary": a.summary, "body": a.body, "tags": a.tags, "rating": a.rating,
		"metadata": map[string]any{"seo": map[string]any{"title": a.title + " | Example Blog", "description": a.summary}, "lang": u.lang[:2]},
	})))
	// A cover: uploaded, then set.
	upload := multipartBody("/files", map[string]string{"title": "Cover: " + a.title}, "file",
		strings.ToLower(strings.ReplaceAll(a.tags[0], " ", "-"))+"-cover.png", "image/png", samplePNG)
	file := r.dxID(r.must(upload))
	r.must(jsonBody(http.MethodPatch, fmt.Sprintf("/files/%v", file), map[string]any{"description": "Photo © " + u.first + " " + u.last + ", 2026", "tags": []string{"cover"}}))
	r.must(jsonBody(http.MethodPatch, fmt.Sprintf("/items/articles/%v", id), map[string]any{"cover": file, "status": "published", "published_at": "2026-11-20T09:30:00.000Z"}))
	r.must(get(api, fmt.Sprintf("/items/articles/%v?fields=*&fields=cover.*&fields=user_created.first_name&fields=user_created.last_name", id)))
	r.must(get(image, fmt.Sprintf("/assets/%v?key=system-large-contain%s", file, r.dxAssetToken())))
	r.must(get(image, fmt.Sprintf("/assets/%v?width=400&height=300&fit=cover&format=webp&quality=80%s", file, r.dxAssetToken())))
	r.must(get(api, fmt.Sprintf("/revisions?filter=%s&sort=-id&limit=10&fields=id,activity.action,activity.timestamp", url.QueryEscape(fmt.Sprintf(`{"collection":{"_eq":"articles"},"item":{"_eq":"%v"}}`, id)))))
	// A draft made and thrown away.
	draft := r.dxID(r.must(jsonBody(http.MethodPost, "/items/articles", map[string]any{"status": "draft", "title": "(brouillon) " + a.title, "body": ""})))
	r.must(request{kind: api, method: http.MethodDelete, path: fmt.Sprintf("/items/articles/%v", draft)})

	// The customers.
	c := dxCustomers[i%len(dxCustomers)]
	cust := r.dxID(r.must(jsonBody(http.MethodPost, "/items/customers", c)))
	r.must(get(api, "/items/customers?limit=25&fields[]=id&fields[]=name&fields[]=country&sort[]=name&filter="+
		url.QueryEscape(`{"country":{"_in":["Ireland","France","Germany","Spain"]}}`)))
	r.must(get(api, "/items/customers?search="+url.QueryEscape(strings.Fields(dxCustomers[(i+1)%len(dxCustomers)]["name"].(string))[0])+"&limit=10"))
	r.must(jsonBody(http.MethodPatch, fmt.Sprintf("/items/customers/%v", cust), map[string]any{
		"notes": c["notes"].(string) + " Updated by " + u.first + ": called back on 2026-11-20 (no answer).",
	}))
	r.must(get(api, "/items/articles?aggregate[count]=id&groupBy[]=status"))
	// GraphQL, as an editor's script in the app would.
	r.must(jsonBody(http.MethodPost, "/graphql", map[string]any{
		"query":     "query Recent($search: String) { articles(search: $search, filter: { status: { _eq: \"published\" } }, sort: [\"-published_at\"], limit: 5) { id title tags published_at } }",
		"variables": map[string]any{"search": r.pick(dxSearches)},
	}))
	if studio {
		r.must(jsonBody(http.MethodPost, "/auth/refresh", map[string]any{"mode": "session"}))
		r.must(jsonBody(http.MethodPost, "/auth/logout", map[string]any{"mode": "session"}))
		return
	}
	var auth struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	r.must(jsonBody(http.MethodPost, "/auth/refresh", map[string]any{"refresh_token": refresh, "mode": "json"})).json(&auth)
	r.token = auth.Data.AccessToken
	r.must(get(api, "/items/articles?fields=id,title&filter[status][_eq]=draft&limit=5"))
	r.must(jsonBody(http.MethodPost, "/auth/logout", map[string]any{"refresh_token": auth.Data.RefreshToken}))
}

// dxAssetToken is the query a front end with a token adds to an image's
// URL (an <img> sends no Authorization header); the Data Studio's cookie
// needs none.
func (r *recorder) dxAssetToken() string {
	if r.token == "" {
		return ""
	}
	return "&access_token=" + r.token
}

// dxStudio: editor i uses the Data Studio (two of them; the others, the
// team's front end).
func dxStudio(i int) bool { return i < 2 }

// dxService is the CRM importer: a service with a static token.
func (r *recorder) dxService() {
	r.ua.userAgent = "crm-sync/2.4.1 (+https://crm.example.com/bot) node-fetch/3.3.2"
	r.token = dxServiceToken
	r.must(get(client, "/server/ping"))
	r.must(get(client, "/users/me?fields=id,email"))
	var batch []map[string]any
	for _, c := range dxCustomers {
		batch = append(batch, map[string]any{"name": c["name"], "email": strings.Replace(c["email"].(string), "@", "+crm@", 1), "country": c["country"],
			"notes": "Imported from the CRM (source: Salesforce export 2026-11-20).", "address": c["address"]})
	}
	var created struct {
		Data []struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	r.must(jsonBody(http.MethodPost, "/items/customers", batch).as(client)).json(&created)
	var keys []int
	for _, c := range created.Data {
		keys = append(keys, c.ID)
	}
	r.must(jsonBody(http.MethodPatch, "/items/customers", map[string]any{"keys": keys, "data": map[string]any{"notes": "Imported; to review (dupes?)"}}).as(client))
	r.must(get(client, "/items/customers?filter[country][_eq]=France&filter[email][_icontains]=example&fields=id,name,email&limit=50"))
	r.must(get(client, "/items/customers?filter[name][_starts_with]="+url.QueryEscape("D'")+"&fields=*"))
	r.must(get(client, "/items/articles?filter[status][_eq]=published&filter[published_at][_gte]=$NOW(-7%20days)&sort=-published_at&fields=id,title,summary,tags"))
	gql := []map[string]any{
		{"query": "{ customers(filter: { country: { _eq: \"Ireland\" } }) { id name email address } }"},
		{"query": "query ($id: ID!) { articles_by_id(id: $id) { id title body tags rating } }", "variables": map[string]any{"id": "1"}},
		{"query": "mutation ($data: create_customers_input!) { create_customers_item(data: $data) { id name } }",
			"variables": map[string]any{"data": map[string]any{"name": "Fatima Al-Hassan", "email": "fatima.alhassan@example.com", "country": "Morocco",
				"notes": "Signed up at the Casablanca fair; wants a demo (Arabic/French).", "address": map[string]any{"city": "Casablanca"}}}},
		{"query": "{ articles_aggregated(groupBy: [\"status\"]) { group count { id } } }"},
	}
	for _, q := range gql {
		r.must(jsonBody(http.MethodPost, "/graphql", q).as(client))
	}
	if len(keys) > 2 {
		r.must(request{kind: client, method: http.MethodDelete, path: "/items/customers", contentType: "application/json", body: mustJSON(keys[len(keys)-2:])})
	}
	r.must(get(client, "/items/customers?aggregate[countDistinct]=country"))
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
