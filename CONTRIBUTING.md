# Contributing to Inkwall

This guide sets the rules for commit messages, pull requests, branch names, testing and releases.

## Contents

- [Commit messages](#commit-messages)
  - [Rules](#rules)
- [Development and testing](#development-and-testing)
- [Branches](#branches)
- [Releases](#releases)
  - [Cutting a release](#cutting-a-release)
  - [Release branches and patches](#release-branches-and-patches)

## Commit messages

Commits follow [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/), and CI
enforces it: the types drive the changelog and the next version.

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
| `build` | Build system, Dockerfiles, [goreleaser](https://goreleaser.com/), dependencies (`build(deps): ...`) | none |
| `ci` | [GitHub Actions](https://docs.github.com/en/actions) and CI configuration | none |
| `chore` | Maintenance that fits nowhere else (tooling config, housekeeping) | none |
| `revert` | Reverts a commit (`revert: feat(engine): ...`, body: `This reverts commit <sha>.`) | depends |
| `security` | Fix for a vulnerability in Inkwall itself | patch |

`!` or a `BREAKING CHANGE:` footer makes a major release (a minor one while on `0.x`).

| Scope | Area |
|---|---|
| `engine` | `pkg/` core engine, pipeline, rules |
| `operator` | `operator/` controllers, CRDs, webhooks |
| `api` | [protobuf](https://protobuf.dev/) definitions in `api/` |
| `envoy`, `nginx`, `traefik`, `haproxy`, `caddy`, `proxy` | adapters (engine side and proxy side) |
| `cli` | `inkwallctl` |
| `helm` | `deploy/helm` chart |
| `rules` | vendored [CRS](https://coreruleset.org/) and builtin rule sets |
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
6. Run `make check` before opening a pull request: it runs the linter, the unit tests, the
   vulnerability scan and the docs checks, in minutes. CI runs much more on every pull request
   ([below](#development-and-testing)); `make check-all` runs all of it locally.

## Development and testing

`make help` lists every target. The tests, by tier: when CI runs each, and what it needs locally.
Durations are on a laptop or a CI runner, roughly.

| Tier | Target | Takes | Needs | CI |
|---|---|---|---|---|
| Fast checks | `make check` (`make lint`, `make test`, `make vuln`, `make docs-check`) | 5–10 min | Go | every PR (`lint`, `test`, `vuln`, `docs`) |
| Unit tests | `make test` (race detector; the operator's against envtest) | 5 min | Go | every PR (`test`) |
| Fuzz seeds | in `make test` (each target's `testdata/fuzz`) | | Go | every PR |
| Fuzzing | `go test -run '^$' -fuzz '^FuzzX$' ./pkg/x` | 5 min per target | Go | nightly (`fuzz`) |
| Stress | `make stress-test` | an hour | Go | nightly (`stress`) |
| Scale | `make scale-test SCALE_CHANGES=5`, `make scale-test SCALE=wiring:500` (`SCALE=full`: the 0004 §8 matrix) | 5 min (`full`: hours) | Go | every PR (`test`) |
| Build | `make build` | 1 min | Go | every PR (`test`) |
| Generated code | `make generate-check` | 2 min | Go | every PR (`generate`) |
| Chart | `make helm-lint`, `make monitoring-test` | 2 min | Go, Helm, Docker (promtool) | every PR (`helm`) |
| Release configuration | `make release-check` | 1 min | goreleaser | every PR (`release`) |
| CRS conformance | `make crs-test` | 2 min | Go | every PR (`crs`) |
| Benchmarks | `make bench-compare` (base: `origin/main`) | 10 min | Go | every PR (`bench`) |
| Images | `make image` | 5 min | Docker | every PR (`image`, both platforms) |
| Proxies in Docker | `make raw-envoy-e2e`, `make websocket-e2e`, `make haproxy-e2e` | 5 min each | Docker | every PR (`raw-envoy`, `haproxy`) |
| End to end on kind | `make kind-e2e` (all), `make kind-e2e-traefik`, `-raw-envoy`, `-envoy-gateway`, `-istio`, `-haproxy` | 25 min (all) | Docker, kind (installed by the target) | every PR (`e2e (<proxy>)`, one job each) |
| Upgrade on kind | `make kind-upgrade` | 15 min | Docker, kind | every PR (`upgrade`, from the latest release); release qualification (`upgrade.yaml`, from each supported minor) |
| Examples | `make test-examples` (each `examples/<proxy>` policy through `inkwallctl test --policy`, and the `examples/tests` suite) | 1 min | Go | every PR (`test`) |
| Quickstart | `make kind-quickstart` (`docs/quickstart.md` as written, released chart and images) | 10 min | Docker, kind, network | nightly (`quickstart`) |
| External links | `make docs-check-external` | 1 min | network | nightly (`docs-links`) |
| Everything a PR runs | `make check-all` | hours | all of the above | |

A failing nightly workflow opens an issue labeled `ci-scheduled-failure`
(`hack/ci/report-scheduled.sh`). `hack/ci`'s tests check that this table names a target for every
`make` target the workflows run, and only targets the Makefile has.

The kind targets (`make kind-up`, `make kind-e2e`, `make kind-upgrade`) install kind `KIND_VERSION`
into `bin/` and run Kubernetes 1.34 (`KIND_NODE_IMAGE` in the Makefile; the operator tests' API
server, `ENVTEST_K8S_VERSION`, runs it too), as CI's upgrade job does. CI's e2e jobs run kind's
newest Kubernetes: one job per proxy (`e2e (traefik)`, `e2e (raw-envoy)`, `e2e (envoy-gateway)`,
`e2e (istio)`, `e2e (haproxy)`), each on its own cluster with the images the `e2e-images` job
built, and the cluster's logs as an artifact when one fails. The chart still installs on 1.29 and
later, untested. A cluster made at another version is recreated with `make kind-down kind-up`.

## Branches

[Trunk-based](https://trunkbaseddevelopment.com/): one long-lived branch, `main`, short-lived work branches, and release branches only
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
- A separately versioned Go module is tagged with its path prefix, [as Go requires](https://go.dev/ref/mod#vcs-version): a future
  Caddy adapter module in `adapters/caddy` would be tagged `adapters/caddy/v0.3.0`.

### Cutting a release

1. Check that CI is green on the commit, and try the build with `make release-snapshot` (binaries
   and archives in `dist/`, nothing signed or published). Then qualify it: tag a release
   candidate (`v0.5.0-rc.1`, as in step 2; the release workflow publishes its images), and run the
   [qualify workflow](.github/workflows/qualify.yaml) with `images: ghcr:0.5.0-rc.1` (Actions,
   "qualify", "Run workflow"). Without a `ref`, it runs that version's own tests (the tag
   `v0.5.0-rc.1`), so a check of a later feature doesn't fail images that predate it; a ref older
   than 0.5.0 can't test published images. It runs every proxy's e2e, the upgrade from each
   supported release, the full scale test with and without responses, the Docker e2e tests and the
   CRS suite against those images. **Cut the release only after a green run**, and link it in the
   release's PR or notes. The same workflow runs nightly on `main` and weekly on the supported
   release branches. The examples that pin the engine image,
   `examples/raw-envoy/kustomization.yaml` (`newTag`), name the release being cut: bump them in
   a PR before tagging. The READMEs write `<version>` (`make docs-check` fails on a pinned
   release there), so they need no bump.
2. Tag it with a [signed, annotated tag](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work) and push the tag:

   ```sh
   git tag -s v0.3.0 -m v0.3.0
   git push origin v0.3.0
   ```

3. The [release workflow](.github/workflows/release.yaml) checks the tag is on `main` or a
   `release-X.Y` branch and that a CI run succeeded on its commit (it waits up to an hour for one
   still running, and publishes nothing without one), then publishes, in order:
   - the images `ghcr.io/inkwall-dev/inkwall-engine` and `ghcr.io/inkwall-dev/inkwall-operator`
     (`0.3.0`, `0.3`, and `latest` for the highest stable version; linux/amd64 and linux/arm64),
     with [SBOM](https://www.cisa.gov/sbom) and [provenance](https://slsa.dev/spec/v1.0/provenance) [attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds);
   - the [Helm](https://helm.sh/docs/) chart [`oci://ghcr.io/inkwall-dev/charts/inkwall`](https://helm.sh/docs/topics/registries/), versioned from the tag (the
     version in `Chart.yaml` is only for development);
   - the binaries, `checksums.txt`, an SPDX SBOM per archive (`<archive>.sbom.json`), build
     provenance attestations of the archives (also attached to the release as
     `inkwall_<version>.intoto.jsonl`), and the GitHub release with the changelog.

   Then it checks what it published, as a user would, release candidates too: the images' and
   the chart's signatures, both platforms and their attestations, `helm pull`, the checksums'
   signature, an archive's checksum and provenance, and `inkwallctl version` from it.

   Images, chart and checksums are signed keyless with [cosign](https://docs.sigstore.dev/cosign/signing/overview/) v3 (`COSIGN_VERSION` in
   the workflow): verify them with cosign v3, as cosign v2 reports "no signatures found". To
   verify an image:

   ```sh
   cosign verify ghcr.io/inkwall-dev/inkwall-engine:<version> \
     --certificate-identity-regexp '^https://github.com/inkwall-dev/inkwall/\.github/workflows/release\.yaml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

   To verify a binary archive: its checksum, the checksums' signature, and its build provenance
   (with the [GitHub CLI](https://cli.github.com/)):

   ```sh
   cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
     --certificate-identity-regexp '^https://github.com/inkwall-dev/inkwall/\.github/workflows/release\.yaml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   sha256sum --check --ignore-missing checksums.txt
   gh attestation verify inkwall_<version>_linux_amd64.tar.gz -R inkwall-dev/inkwall
   ```

   The provenance is also a release asset, `inkwall_<version>.intoto.jsonl` (the attestation's
   [Sigstore bundle](https://docs.sigstore.dev/about/bundle/), one JSON line, covering every
   archive): to verify against it instead of the attestation stored on GitHub, download it next
   to the archive and add `--bundle`:

   ```sh
   gh attestation verify inkwall_<version>_linux_amd64.tar.gz -R inkwall-dev/inkwall \
     --bundle inkwall_<version>.intoto.jsonl
   ```

4. The first time, make the three new [GHCR](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) packages (`inkwall-engine`, `inkwall-operator`,
   `charts/inkwall`) public in the organization's package settings: they are created private.

A failed run can be re-run from the Actions tab. If something was already published, fix it on
`main` and release the next patch instead of moving the tag.

### Release branches and patches

- When a minor version is released, cut `release-X.Y` from its tag (`release-0.3` from `v0.3.0`).
- Fixes land on `main` first, are cherry-picked to the supported release branches
  (`git cherry-pick -x`), and the patch is tagged from the release branch: `v0.3.1`.
- The latest **three** minor versions get fixes; security fixes may be backported further when
  practical.
- Release branches never receive features.
