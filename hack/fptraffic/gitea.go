// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// giteaApp is Gitea (https://about.gitea.com, MIT), a code forge: a
// server-rendered web UI with fetch calls, and a REST API its users'
// scripts and tools call with a token. Each user signs up, fills their
// profile and uploads an avatar, creates a repository, and makes a token
// for a script, which adds files (Markdown, code, YAML), labels, a
// milestone, issues and a pull request through the API, and searches,
// reads and edits them. In the web UI the user previews and posts an
// issue with an attachment, comments on another user's issue, stars a
// repository, searches, and signs out. Issues and comments are written as
// developers write them: Markdown with code blocks, shell commands, SQL,
// stack traces and paths.
var giteaApp = app{
	about:    "Gitea's traffic (its web UI and REST API), played by hack/fptraffic",
	public:   "https://code.example.com",
	sessions: 5,
	jar:      true,
	session:  (*recorder).giteaUser,
}

type giteaUser struct {
	login, email, password, name, website, location, bio string
	// client is the User-Agent of the user's scripts.
	client string
	repo   string
}

var giteaUsers = []giteaUser{
	{"siobhan", "siobhan.oconnor@example.com", "Gr33n-Fields!2026", "Siobhán O'Connor", "https://siobhan.example.com",
		"Dublin, Ireland", "Backend developer. Go, Postgres & a bit of Rust; opinions are my own.", "curl/8.17.0", "billing-service"},
	{"jlefevre", "jl.lefevre+code@example.org", "C'est-la-vie_99", "Jean-Luc Lefèvre", "https://lefevre.example.org/blog/",
		"Paris — Île-de-France", "Ingénieur DevOps : Kubernetes, Terraform et café ☕", "python-requests/2.32.5", "infra-modules"},
	{"anna.ms", "anna.mueller@example.de", "Sommer#Regen&Wind", "Anna Müller-Schmidt", "",
		"München", "Frontend (TypeScript/Vue). Maintainer of a few small libs.", "tea/0.11.1", "ui-components"},
	{"dangelo", "dangelo.smith@example.net", "P@ssw0rd; it's long", "D'Angelo Smith Jr.", "https://dangelo.example.net",
		"Washington, D.C.", "SRE @ a small startup. On-call survivor <3", "Go-http-client/2.0", "runbooks"},
	{"mjgarcia", "mj_garcia@example.es", "contraseña<segura>1", "María José García-López", "",
		"Madrid", "Data engineer: SQL, dbt, Airflow. ¡Hola!", "axios/1.13.2", "etl-pipelines"},
}

// giteaFile is a file a user's script adds to their repository.
type giteaFile struct{ path, message, content string }

var giteaFiles = [][]giteaFile{
	{
		{"README.md", "docs: add a README", "# billing-service\n\nInvoices & payments for the shop.\n\n## Run it\n\n```sh\nexport DATABASE_URL='postgres://billing:billing@localhost:5432/billing?sslmode=disable'\ngo run ./cmd/billing --listen :8080\n```\n\nThen `curl -s localhost:8080/healthz | jq .`\n"},
		{"migrations/0003_invoices.sql", "feat: add the invoices table", "-- 0003: invoices\nCREATE TABLE invoices (\n  id BIGSERIAL PRIMARY KEY,\n  customer_id BIGINT NOT NULL REFERENCES customers(id),\n  total_cents INTEGER NOT NULL CHECK (total_cents >= 0),\n  status TEXT NOT NULL DEFAULT 'draft',\n  created_at TIMESTAMPTZ NOT NULL DEFAULT now()\n);\nCREATE INDEX invoices_customer ON invoices (customer_id, created_at DESC);\n"},
	},
	{
		{"README.md", "docs: README", "# infra-modules\n\nModules Terraform pour nos clusters.\n\n```hcl\nmodule \"cluster\" {\n  source = \"./modules/cluster\"\n  name   = \"prod-eu-west\"\n  nodes  = 3\n}\n```\n"},
		{"scripts/bootstrap.sh", "chore: bootstrap script", "#!/usr/bin/env bash\nset -euo pipefail\n# Installe les outils\nfor tool in terraform kubectl helm; do\n  command -v \"$tool\" >/dev/null || { echo \"missing: $tool\" >&2; exit 1; }\ndone\nterraform -chdir=envs/prod init -upgrade\nkubectl get nodes -o wide | grep -v NotReady || true\n"},
	},
	{
		{"README.md", "docs: add README", "# ui-components\n\nSmall Vue 3 components.\n\n```ts\nimport { DatePicker } from '@example/ui-components'\n\napp.component('DatePicker', DatePicker)\n```\n\n<details><summary>Browser support</summary>\n\nLast 2 versions of Chrome, Firefox & Safari.\n</details>\n"},
		{"src/format.ts", "feat: formatPrice", "export function formatPrice(cents: number, locale = 'de-DE'): string {\n  return new Intl.NumberFormat(locale, { style: 'currency', currency: 'EUR' }).format(cents / 100)\n}\n\n// formatPrice(1999) === '19,99 €'\n"},
	},
	{
		{"README.md", "docs: runbooks index", "# Runbooks\n\n- [Disk full](disk-full.md)\n- [Certificate expiry](certs.md)\n- [High 5xx rate](5xx.md)\n"},
		{"disk-full.md", "docs: disk full runbook", "# Disk full\n\n1. Find the biggest directories:\n\n   ```sh\n   sudo du -xh / --max-depth=2 2>/dev/null | sort -rh | head -20\n   ```\n\n2. Old journal logs: `sudo journalctl --vacuum-time=7d`\n3. Docker: `docker system prune -af --volumes` (**not** on the DB host!)\n4. Check `/var/log/nginx/*.log` rotation: `cat /etc/logrotate.d/nginx`\n"},
	},
	{
		{"README.md", "docs: README", "# etl-pipelines\n\nDAGs de Airflow y modelos dbt.\n\n| Modelo | Fuente | Frecuencia |\n|---|---|---|\n| `orders_daily` | `raw.orders` | diaria |\n| `customers` | `raw.crm` | horaria |\n"},
		{"models/orders_daily.sql", "feat: orders_daily model", "select\n  date_trunc('day', o.created_at) as day,\n  count(*) as orders,\n  sum(o.total) as revenue\nfrom {{ ref('stg_orders') }} o\nwhere o.status <> 'cancelled'\n  and o.created_at >= current_date - interval '90 days'\ngroup by 1\norder by 1 desc\n"},
	},
}

// Issues as developers write them.
var giteaIssues = []struct{ title, body string }{
	{"Invoice total is off by one cent for 3+ items", "Steps to reproduce:\n\n1. Add 3 items at 0.333 €\n2. Check out\n3. The invoice says `0.99`, the cart said `1.00`\n\n```\npanic: runtime error: index out of range [3] with length 3\n\ngoroutine 1 [running]:\nmain.total(...)\n\t/src/billing/total.go:42 +0x1d\n```\n\nProbably the rounding in `total()`; see #1."},
	{"Le module cluster échoue avec terraform 1.13", "Avec `terraform 1.13.4` :\n\n```\nError: Unsupported argument\n  on modules/cluster/main.tf line 12, in resource \"aws_eks_cluster\" \"this\":\n  12:   version = var.k8s_version\n```\n\nQuelqu'un a une idée ? Merci d'avance !"},
	{"DatePicker: wrong first day of week for de-DE", "In `de-DE` the week should start on Monday (Montag), but it starts on Sunday.\n\nExpected: `Mo Di Mi Do Fr Sa So`\nActual: `So Mo Di Mi Do Fr Sa`\n\nTested in Firefox 144 & Chrome 141. Screenshot attached."},
	{"Runbook for 5xx: add the query we used last night", "The query that found it:\n\n```sql\nSELECT path, count(*) AS errors\nFROM access_log\nWHERE status >= 500 AND ts > now() - interval '1 hour'\nGROUP BY path\nORDER BY errors DESC\nLIMIT 10;\n```\n\nAnd the one-liner: `awk '$9 >= 500 {print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head`"},
	{"orders_daily: los pedidos cancelados cuentan", "El modelo filtra `status <> 'cancelled'` pero en `raw.orders` hay también `'canceled'` (con una sola L). ¿Usamos `not in ('cancelled', 'canceled')`?"},
}

var giteaComments = []string{
	"Thanks for the report! I can reproduce it on `main` (a1b2c3d). Will look into it tomorrow.",
	"+1, same here. Workaround: pin the version in `versions.tf` for now:\n\n```hcl\nrequired_version = \"< 1.13\"\n```",
	"Fixed in the latest commit, can you check again? If it's still broken, please paste the output of `go version && go env GOOS GOARCH`.",
	"Looks good to me :+1: — one nit: the `ORDER BY` could use the index if we add `created_at` to it.",
	"Merci ! C'est corrigé. / ¡Gracias! / Danke!",
}

var giteaSearches = []string{"billing", "terraform module", "date picker", "runbook", "etl", "café", "C++", "user's guide", "v1.0 (beta)"}

var giteaUID = regexp.MustCompile(`name="uid" value="([0-9]+)"`)

func (r *recorder) giteaUser(n int) {
	u := giteaUsers[n%len(giteaUsers)]
	r.page("/")
	r.page("/explore/repos")
	r.page("/user/sign_up")
	r.follow(r.must(formBody("/user/sign_up", "user_name", u.login, "email", u.email, "password", u.password, "retype", u.password)))

	// The profile, and an avatar.
	r.page("/user/settings")
	r.follow(r.must(formBody("/user/settings", "name", u.login, "full_name", u.name, "description", u.bio,
		"website", u.website, "location", u.location, "visibility", "0", "keep_email_private", "on")))
	avatar := multipartBody("/user/settings/avatar", map[string]string{"source": "local"}, "avatar", u.login+".png", "image/png", samplePNG)
	avatar.kind = document
	r.follow(r.must(avatar))

	// A repository.
	uid := find(r.page("/repo/create").body, giteaUID)
	r.follow(r.must(formBody("/repo/create", "uid", uid, "repo_name", u.repo,
		"description", giteaFiles[n%len(giteaFiles)][0].content[2:strings.IndexByte(giteaFiles[n%len(giteaFiles)][0].content, '\n')]+" — "+u.name+"'s project",
		"repo_template", "", "issue_labels", "", "gitignores", "Go", "license", "MIT", "readme", "Default", "auto_init", "on",
		"default_branch", "main", "object_format_name", "sha1")))
	repo := "/" + u.login + "/" + u.repo

	// A token for the user's scripts, made with their password.
	r.page("/user/settings/applications")
	basic := base64.StdEncoding.EncodeToString([]byte(u.login + ":" + u.password))
	r.ua.userAgent = u.client
	r.token, r.scheme = basic, "Basic"
	resp := r.must(jsonBody(http.MethodPost, "/api/v1/users/"+u.login+"/tokens", map[string]any{
		"name": "ci-" + u.repo, "scopes": []string{"write:repository", "write:issue", "write:user", "read:organization"},
	}).as(client))
	var tok struct {
		SHA1 string `json:"sha1"`
	}
	if !resp.json(&tok) || tok.SHA1 == "" {
		panic(sessionError{fmt.Errorf("token for %s: status %d", u.login, resp.status)})
	}
	r.token, r.scheme = tok.SHA1, "token"
	r.giteaScript(n, u, repo)
	r.token, r.scheme = "", ""
	r.ua = browsers[n%len(browsers)]

	// The web UI.
	r.page(repo)
	r.page(repo + "/src/branch/main/" + giteaFiles[n%len(giteaFiles)][1].path)
	r.page(repo + "/issues")
	r.page(repo + "/issues?type=all&state=open&q=" + url.QueryEscape(r.pick(giteaSearches)))
	r.page(repo + "/issues/new")
	issue := giteaIssues[(n+2)%len(giteaIssues)]
	r.must(formBody(repo+"/markup", "mode", "comment", "context", repo, "text", issue.body).as(api))
	att := multipartBody(repo+"/issues/attachments", nil, "file", "screenshot-"+fmt.Sprint(n+1)+".png", "image/png", samplePNG)
	var uuid struct {
		UUID string `json:"uuid"`
	}
	r.must(att).json(&uuid)
	r.follow(r.must(formBody(repo+"/issues/new", "title", issue.title+" (UI)", "content", issue.body+"\n\n![screenshot](/attachments/"+uuid.UUID+")",
		"files", uuid.UUID, "label_ids", "", "milestone_id", "", "project_ids", "", "assignee_ids", "", "redirect_after_creation", "").as(api)))
	// Another user's issue: a comment, and a star.
	if n > 0 {
		o := giteaUsers[(n-1)%len(giteaUsers)]
		other := "/" + o.login + "/" + o.repo
		r.page(other)
		r.page(other + "/issues/1")
		r.must(formBody(other+"/markup", "mode", "comment", "context", other, "text", giteaComments[n%len(giteaComments)]).as(api))
		r.follow(r.must(formBody(other+"/issues/1/comments", "content", giteaComments[n%len(giteaComments)], "status", "").as(api)))
		r.must(formBody(other + "/action/star").as(api))
	}
	r.page("/explore/repos?q=" + url.QueryEscape(r.pick(giteaSearches)) + "&sort=recentupdate")
	r.page("/explore/users?q=" + url.QueryEscape(strings.Fields(giteaUsers[(n+1)%len(giteaUsers)].name)[0]))
	r.page("/" + u.login)
	r.follow(r.must(get(document, "/user/logout")))
}

// giteaScript is the user's script: the REST API, with their token.
func (r *recorder) giteaScript(n int, u giteaUser, repo string) {
	api := "/api/v1/repos" + repo
	r.must(get(client, "/api/v1/user"))
	r.must(get(client, "/api/v1/version"))
	r.must(get(client, api))
	files := giteaFiles[n%len(giteaFiles)]
	for i, f := range files {
		body := map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(f.content)), "message": f.message, "branch": "main"}
		if i == 0 {
			// The README the repository was made with: updated, with its SHA.
			var cur struct {
				SHA string `json:"sha"`
			}
			r.must(get(client, api+"/contents/"+f.path+"?ref=main")).json(&cur)
			body["sha"] = cur.SHA
			r.must(jsonBody(http.MethodPut, api+"/contents/"+f.path, body).as(client))
			continue
		}
		r.must(jsonBody(http.MethodPost, api+"/contents/"+f.path, body).as(client))
	}
	r.must(get(client, api+"/commits?sha=main&limit=10"))
	r.must(get(client, api+"/raw/"+files[1].path+"?ref=main"))
	labels := []map[string]any{
		{"name": "bug", "color": "#ee0701", "description": "Something isn't working"},
		{"name": "good first issue", "color": "#7057ff", "description": "Good for newcomers :)"},
		{"name": "wontfix", "color": "#ffffff", "description": "This will not be worked on"},
	}
	var labelIDs []int
	for _, l := range labels {
		labelIDs = append(labelIDs, dataIDOf(r.must(jsonBody(http.MethodPost, api+"/labels", l).as(client))))
	}
	r.must(request{kind: client, method: http.MethodDelete, path: fmt.Sprintf("%s/labels/%d", api, labelIDs[2])})
	r.must(jsonBody(http.MethodPost, api+"/milestones", map[string]any{
		"title": "v1.0 — first release", "description": "Everything for the 1.0 release (incl. docs & migration guide)", "due_on": "2027-03-31T00:00:00Z",
	}).as(client))
	r.must(jsonBody(http.MethodPut, api+"/topics", map[string]any{"topics": []string{"go", "self-hosted", "example"}}).as(client))
	issue := giteaIssues[n%len(giteaIssues)]
	id := dataIDOf(r.must(jsonBody(http.MethodPost, api+"/issues", map[string]any{
		"title": issue.title, "body": issue.body, "labels": labelIDs[:1],
	}).as(client)))
	r.must(get(client, fmt.Sprintf("%s/issues/%d", api, id)))
	r.must(jsonBody(http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", api, id), map[string]any{
		"body": giteaComments[(n+1)%len(giteaComments)],
	}).as(client))
	r.must(jsonBody(http.MethodPatch, fmt.Sprintf("%s/issues/%d", api, id), map[string]any{
		"title": issue.title + " [confirmed]", "labels": labelIDs[:2],
	}).as(client))
	r.must(get(client, api+"/issues?state=all&type=issues&q="+url.QueryEscape(strings.Fields(issue.title)[0])+"&labels=bug&limit=20"))
	// A branch, a change on it, and a pull request.
	r.must(jsonBody(http.MethodPost, api+"/branches", map[string]any{"new_branch_name": "fix/issue-1", "old_branch_name": "main"}).as(client))
	var cur struct {
		SHA string `json:"sha"`
	}
	r.must(get(client, api+"/contents/"+files[1].path+"?ref=fix/issue-1")).json(&cur)
	r.must(jsonBody(http.MethodPut, api+"/contents/"+files[1].path, map[string]any{
		"content": base64.StdEncoding.EncodeToString([]byte(files[1].content + "\n# fixed: see #1\n")),
		"message": "fix: the issue in #1", "branch": "fix/issue-1", "sha": cur.SHA,
	}).as(client))
	r.must(jsonBody(http.MethodPost, api+"/pulls", map[string]any{
		"head": "fix/issue-1", "base": "main", "title": "Fix #1: " + issue.title,
		"body": "Closes #1.\n\n- [x] tests\n- [ ] docs\n\nReviewers: please check the `CHANGELOG` too.",
	}).as(client))
	r.must(get(client, api+"/pulls?state=open"))
	r.must(jsonBody(http.MethodPost, "/api/v1/markdown", map[string]any{"Text": issue.body, "Mode": "gfm", "Context": repo}).as(client))
	r.must(get(client, "/api/v1/repos/search?q="+url.QueryEscape(r.pick(giteaSearches))+"&limit=10"))
	r.must(request{kind: client, method: http.MethodPut, path: "/api/v1/user/starred" + repo})
	r.must(jsonBody(http.MethodPatch, api, map[string]any{"description": "Updated by our CI — " + u.name, "website": u.website, "has_wiki": false}).as(client))
}

// dataIDOf is the id of the object a REST API answers with.
func dataIDOf(resp response) int {
	var v struct {
		ID     int `json:"id"`
		Number int `json:"number"`
	}
	resp.json(&v)
	if v.Number != 0 {
		return v.Number
	}
	return v.ID
}
