# Contributing to Inkwall

## Commit messages

Inkwall follows [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/).
Commit types drive the changelog and the next release version, so they are enforced in CI.

### Format

```
<type>(<scope>)!: <subject>

<body>

<footer>
```

- `type`: required, from the list below.
- `scope`: optional but recommended, from the list below.
- `!`: marks a breaking change (also add a `BREAKING CHANGE:` footer).
- `subject`: required, imperative mood ("add", not "added"/"adds"), lowercase, no trailing period,
  at most 72 characters for the whole first line.
- `body`: optional, wrapped at 72 columns, explains **why** the change is needed, not what the diff
  shows.
- `footer`: optional; `BREAKING CHANGE: <description>`, `Refs: #123`, `Closes: #123`.

### Types

| Type | Use for | Release effect |
|---|---|---|
| `feat` | A new user-facing capability | minor |
| `fix` | A bug fix | patch |
| `perf` | A change that improves performance with no behaviour change | patch |
| `refactor` | Code change that neither fixes a bug nor adds a feature | none |
| `docs` | Documentation only (including `docs/design`) | none |
| `test` | Adding or fixing tests, benchmarks, corpus entries | none |
| `build` | Build system, Dockerfiles, goreleaser, dependencies (`build(deps): ...`) | none |
| `ci` | GitHub Actions and CI configuration | none |
| `chore` | Maintenance that doesn't fit elsewhere (tooling config, repo housekeeping) | none |
| `revert` | Reverts a previous commit (`revert: feat(engine): ...`, body: `This reverts commit <sha>.`) | depends |
| `security` | Fix for a security vulnerability in Inkwall itself | patch |

Any type with `!` or a `BREAKING CHANGE:` footer triggers a major release (while the version is
`0.x`, it triggers a minor release instead).

### Scopes

| Scope | Area |
|---|---|
| `engine` | `pkg/` core engine, pipeline, rules |
| `operator` | `operator/` controllers, CRDs, webhooks |
| `api` | protobuf definitions in `api/` |
| `envoy`, `nginx`, `traefik`, `haproxy`, `caddy`, `proxy` | adapters (engine side and proxy side) |
| `cli` | `inkwallctl` |
| `helm` | `deploy/helm` chart |
| `rules` | vendored CRS and builtin rule sets |
| `design` | design documents in `docs/design` |
| `deps` | dependency updates |

A change spanning several scopes either omits the scope or is split into several commits.

### Examples

```
feat(engine): add sharded token bucket rate limiter
fix(nginx): keep cosocket alive after deny verdict
perf(engine): pool coraza transactions to remove per-request allocs
docs(design): add operator uninstall flow
feat(operator)!: rename WAFPolicy.spec.rules to ruleSets

BREAKING CHANGE: WAFPolicy.spec.rules is renamed to spec.ruleSets.
Existing objects must be updated before upgrading.
```

### Rules

1. One logical change per commit; don't mix a refactor with a feature.
2. Every commit on `main` must build and pass tests.
3. Pull requests are squash-merged; the PR title must itself be a valid conventional commit, since
   it becomes the commit on `main`.
4. No AI or tool attribution trailers (e.g. `Co-Authored-By` for tools) in commit messages.
5. Every pull request has an issue. Open the issue first, give it a label (`enhancement`, `bug`,
   `documentation`, ...), and link it from the PR by starting the PR description with
   `Closes #<issue>`, so merging the PR closes the issue.

## Branches and releases

Inkwall uses **trunk-based development**: one long-lived branch, `main`, short-lived work
branches, and release branches only for patching released versions.

### `main`

- Always releasable. Protected: no direct pushes, required CI checks, at least one approving
  review, linear history.
- Pull requests are squash-merged (see [Rules](#rules)); the PR title becomes the commit message.

### Work branches

- Branch from `main`, named `<type>/<short-description>`, using the commit types above:
  `feat/engine-rate-limiter`, `fix/nginx-keepalive`, `docs/design-operator`, `ci/benchstat-gate`.
- Keep them short-lived: merge within days, not weeks. Rebase on `main` instead of merging `main`
  into the branch.
- Large features land in small PRs. Unfinished work is merged behind a flag or left unwired, never
  kept on a long-running branch.
- Branches are deleted after merge.

### Releases

- A release is a **tag on `main`**: `v0.3.0`. goreleaser builds and publishes from the tag, and the
  changelog is generated from commit types.
- Versions follow [Semantic Versioning](https://semver.org/). While on `0.x`, breaking changes bump
  the minor version.
- Pre-releases use suffixes: `v0.3.0-rc.1`.
- Separately versioned Go modules are tagged with their path prefix, as Go requires:
  `adapters/caddy/v0.3.0`, `adapters/traefik-plugin/v0.3.0`.

### Release branches and patches

- When a minor version is released, cut `release-X.Y` from its tag (e.g. `release-0.3` from
  `v0.3.0`).
- Fixes always land on `main` first, then are cherry-picked to the supported release branches
  (`git cherry-pick -x`), and the patch is tagged from the release branch: `v0.3.1`.
- The last **three** minor versions are supported with fixes; security fixes may be backported
  further when practical.
- Release branches never receive features.
