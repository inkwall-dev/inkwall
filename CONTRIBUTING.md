# Contributing to Inkwall

## Commit messages

Commits follow [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/), enforced
in CI: the types drive the changelog and the next version.

```
<type>(<scope>)!: <subject>

<body>

<footer>
```

- `type`: required, from the table below. `scope`: optional but recommended.
- `!`: a breaking change; also add a `BREAKING CHANGE:` footer.
- `subject`: imperative ("add", not "added"/"adds"), lowercase, no trailing period; the whole first
  line at most 72 characters.
- `body`: optional, wrapped at 72 columns; explains **why**, not what the diff shows.
- `footer`: optional: `BREAKING CHANGE: <description>`, `Refs: #123`, `Closes: #123`.

| Type | Use for | Release |
|---|---|---|
| `feat` | A new user-facing capability | minor |
| `fix` | A bug fix | patch |
| `perf` | Better performance, no behaviour change | patch |
| `refactor` | Neither a fix nor a feature | none |
| `docs` | Documentation only (including `docs/design`) | none |
| `test` | Tests, benchmarks, corpus entries | none |
| `build` | Build system, Dockerfiles, goreleaser, dependencies (`build(deps): ...`) | none |
| `ci` | GitHub Actions and CI configuration | none |
| `chore` | Maintenance that fits nowhere else (tooling config, housekeeping) | none |
| `revert` | Reverts a commit (`revert: feat(engine): ...`, body: `This reverts commit <sha>.`) | depends |
| `security` | Fix for a vulnerability in Inkwall itself | patch |

`!` or a `BREAKING CHANGE:` footer makes a major release (a minor one while on `0.x`).

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

A change spanning several scopes omits the scope or is split into several commits.

```
feat(engine): add sharded token bucket rate limiter
fix(nginx): keep cosocket alive after deny verdict
docs(design): add operator uninstall flow
feat(operator)!: rename WAFPolicy.spec.rules to ruleSets

BREAKING CHANGE: WAFPolicy.spec.rules is renamed to spec.ruleSets.
Existing objects must be updated before upgrading.
```

### Rules

1. One logical change per commit; don't mix a refactor with a feature.
2. Every commit on `main` builds and passes tests.
3. Pull requests are squash-merged; the PR title must be a valid conventional commit, since it
   becomes the commit on `main`.
4. No AI or tool attribution trailers (e.g. `Co-Authored-By` for tools) in commit messages.
5. Every pull request has an issue. Open the issue first with a label (`enhancement`, `bug`,
   `documentation`, ...), and start the PR description with `Closes #<issue>`, so merging the PR
   closes it.

## Branches

Trunk-based: one long-lived branch, `main`, short-lived work branches, and release branches only
for patching released versions.

- `main` is always releasable and protected: no direct pushes, required CI checks, at least one
  approving review, linear history.
- Work branches start from `main` and are named `<type>/<short-description>` with the commit types
  above: `feat/engine-rate-limiter`, `fix/nginx-keepalive`, `docs/design-operator`.
- Keep them short-lived (days, not weeks), and rebase on `main` rather than merging `main` in.
- Large features land in small PRs; unfinished work is merged behind a flag or left unwired, never
  kept on a long-running branch.
- Branches are deleted after merge.

## Releases

- A release is a **tag on `main`**, e.g. `v0.3.0`; the changelog is generated from the commit types.
- Versions follow [Semantic Versioning](https://semver.org/); on `0.x`, breaking changes bump the
  minor version. Pre-releases use suffixes: `v0.3.0-rc.1`.
- Separately versioned Go modules are tagged with their path prefix, as Go requires (e.g.
  `adapters/caddy/v0.3.0`).

### Cutting a release

1. Check that CI is green on the commit, and try the build with `make release-snapshot` (binaries
   and archives in `dist/`, nothing signed or published).
2. Tag it with a signed, annotated tag and push the tag:

   ```sh
   git tag -s v0.3.0 -m v0.3.0
   git push origin v0.3.0
   ```

3. The [release workflow](.github/workflows/release.yaml) checks the tag is on `main` or a
   `release-X.Y` branch, then publishes, in order:
   - the images `ghcr.io/inkwall-dev/inkwall-engine` and `ghcr.io/inkwall-dev/inkwall-operator`
     (`0.3.0`, `0.3`, and `latest` for the highest stable version; linux/amd64 and linux/arm64),
     with SBOM and provenance attestations;
   - the Helm chart `oci://ghcr.io/inkwall-dev/charts/inkwall`, versioned from the tag (the
     version in `Chart.yaml` is only for development);
   - the binaries, `checksums.txt` and the GitHub release with the changelog.

   Images, chart and checksums are signed keyless with cosign. To verify an image:

   ```sh
   cosign verify ghcr.io/inkwall-dev/inkwall-engine:0.3.0 \
     --certificate-identity-regexp '^https://github.com/inkwall-dev/inkwall/\.github/workflows/release\.yaml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

4. The first time, make the three new GHCR packages (`inkwall-engine`, `inkwall-operator`,
   `charts/inkwall`) public in the organization's package settings: they are created private.

A failed run can be re-run from the Actions tab. If something was already published, fix it on
`main` and release the next patch instead of moving the tag.

### Release branches and patches

- When a minor version is released, cut `release-X.Y` from its tag (`release-0.3` from `v0.3.0`).
- Fixes land on `main` first, are cherry-picked to the supported release branches
  (`git cherry-pick -x`), and the patch is tagged from the release branch: `v0.3.1`.
- The last **three** minor versions get fixes; security fixes may be backported further when
  practical.
- Release branches never receive features.
