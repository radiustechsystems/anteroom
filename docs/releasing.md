# Releasing Anteroom

The gate ships as a container image on GitHub Container Registry. A release is an
annotated git tag pushed to this repository; everything after that is
[`.github/workflows/release.yaml`](../.github/workflows/release.yaml).

```sh
docker pull ghcr.io/radiustechsystems/anteroom:latest
```

This document is the contract for what the tags on that image mean. It matters
more than it looks: an operator who pins `:1` is being told something about
what will and will not change under them, and a tag policy that is only in a
workflow file is a promise nobody can read.

---

## The one-minute version

| To release | Do |
|---|---|
| `v1.4.0` | `git tag -a v1.4.0 -m v1.4.0 && git push origin v1.4.0` |
| `v1.4.0-beta.1` | the same, with the prerelease tag |

A tag push is the only thing that publishes. There is no button, and no build
off a branch: the trigger is someone stating that a specific tree is the thing
other people should run.

Tag a commit **on main** — nothing publishes from off main, and that is the first
thing the run checks. Then it runs the full suite — unit tests, vet, staticcheck,
govulncheck, and every acceptance tier, browser included — and publishes nothing
if any of it fails.

---

## Versioning

Semver, and Anteroom is pre-1.0, so the middle number is where breakage lives.
Concretely, until `v1.0.0`:

- **`0.x.y` → `0.(x+1).0`** may change configuration keys, cookie or challenge
  formats, or the wait-page contract. Read the release notes.
- **`0.x.y` → `0.x.(y+1)`** is fixes and additions only. Safe to take blind.

What counts as a breaking change here is broader than the Go API, which nobody
imports. It is the operator-visible surface: `anteroom.toml` keys, the four
`ANTEROOM_*` environment variables, the `/.anteroom/*` endpoints, pass and
challenge encodings (an incompatible change walls every visitor holding a pass
issued by the old version), metric names, and the image's own contract — the
config path, the state directory, the UID, the exposed port.

Post-1.0 the same list moves under the major number and the rules become the
ordinary ones.

## What gets published, and which tags move

One tag push produces one multi-arch image (`linux/amd64`, `linux/arm64`) and
several names for it:

| Git tag | Image tags |
|---|---|
| `v1.4.0` | `1.4.0`, `1.4`, `1`, `latest`, `sha-<commit>` |
| `v0.4.0` | `0.4.0`, `0.4`, `latest`, `sha-<commit>` |
| `v1.4.0-beta.1` | `1.4.0-beta.1`, `beta`, `sha-<commit>` |

Three of those are decisions rather than defaults:

**A prerelease never moves `latest`, `1.4`, or `1`.** Those are the tags people
pin *because* they want to be spared surprises. A beta is the one build that has
not earned them. It gets its own exact tag and moves `beta`, which is the
pointer for anyone who asked for the edge of the next release.

**There is no `:0` tag.** Under semver 0.x, `0.4 → 0.5` is where an
incompatibility is allowed to appear, so a `0` tag would pin nothing while
looking like it pinned something. It reappears at `v1.0.0`, where it means what
it says.

**`sha-<commit>` is the full hash, not a prefix**, so it can be pasted into
`git show`. Every build gets one, betas included — it is the only tag that is
never reused.

## What to pin

| You are | Pin | Because |
|---|---|---|
| running this in front of a real site | `@sha256:…` (from the release page) | The only name that cannot change under you. |
| running it in front of a real site, and want patches | `:1.4` (or `:0.4` pre-1.0) | Fixes, no surface changes. |
| kicking the tyres | `:latest` | Fine. Not fine in production, where "whatever shipped this morning" is not a deployment decision. |
| testing the next release | `:beta` | Moves to each new prerelease. |

`:latest` deserves the emphasis. Anteroom sits in the request path of someone
else's site, and a floating tag plus an image pull policy of `Always` means a
restart can change the gate. Pin the digest, watch the releases, and take
upgrades when you meant to.

## Betas

Use one when a change touches the operator-visible surface above — a config key,
a pass format, the wait-page contract — and you want it run somewhere real before
`latest` moves.

```sh
git tag -a v0.5.0-beta.1 -m v0.5.0-beta.1 && git push origin v0.5.0-beta.1
# …find something, fix it, then
git tag -a v0.5.0-beta.2 -m v0.5.0-beta.2 && git push origin v0.5.0-beta.2
# …happy, then
git tag -a v0.5.0 -m v0.5.0 && git push origin v0.5.0
```

Increment the counter; never move a prerelease tag that has been pushed. Its
image is published and possibly running, and a tag that means two different
things is worse than a wasted number. The GitHub Release is created with the
prerelease flag set, so `/releases/latest` and everything that reads it keep
pointing at the last real release.

## Only main gets published

The tag has to point at a commit in main's history. Nothing else publishes, and
the check is the first job in the run, so a mistagged commit costs ten seconds
rather than a `:latest` that has to be explained afterwards.

A tag is a ref, not a lineage. `git tag v9.9.9` on a feature branch, a fork's
history, or a commit that never went through review is a perfectly valid tag
push, and without the gate it would put an image on the registry that no
reviewed history contains.

It tests ancestry rather than equality — main moves on after a tag is cut, and a
tag from last week is still a release. One consequence worth stating: **a
squash-merged commit is refused.** Its original SHA is not in main, so main does
not contain the tree you tagged, whatever the diff looked like. Tag the commit on
main, not the branch it came from.

There is no exemption and no dry run. To exercise the release path without
publishing, run `make image` and `make acceptance` locally — Tier 0 builds and
grades the image, which is the part a dry run was checking.

## Cutting a release

1. `make check` and `make acceptance` locally. The workflow runs both, but
   finding out from a tag push is an expensive way to learn.
2. Tag an annotated tag on a commit that is **on main**, and push it.
3. Watch the run. It checks the commit is on main, verifies, builds both
   architectures, pushes, signs,
   attaches an SBOM and provenance, then **pulls the published image back and
   starts it** — the last step grades the bytes a user gets rather than the ones
   the runner built.
4. The Release page is created with a generated changelog, the pull command, and
   the digest.

A release that goes wrong is fixed forward: cut the next patch. Deleting a
published version is possible from the package settings, but anything that
already pulled it has it, and the signature and provenance for that digest stay
valid — which is correct, because they attest what was built, not whether it was
a good idea.

## Verifying what you pulled

The image is signed keylessly, so there is no signing key anywhere to leak: the
signature is bound to the release workflow's identity in the repository that ran
it — which is why the identity below is a repository path and has to match the
one that cut the release.

```sh
cosign verify ghcr.io/radiustechsystems/anteroom:0.4.0 \
  --certificate-identity-regexp '^https://github.com/radiustechsystems/anteroom/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The SBOM and provenance travel with the image:

```sh
cosign download sbom ghcr.io/radiustechsystems/anteroom:0.4.0
docker buildx imagetools inspect ghcr.io/radiustechsystems/anteroom:0.4.0 \
  --format '{{ json .Provenance }}'
```

## Which code is actually running

Ask the gate. `.git` is excluded from the build context on purpose, so the
toolchain cannot stamp the binary; the workflow passes both values as build args
and they come out on `/metrics`:

```
anteroom_build_info{version="v0.4.0",revision="<full commit>",…} 1
```

`version` is the git tag verbatim — `v0.4.0`, not `0.4.0` — and `revision` is
the commit it was built from. An image built without those build args reports
`version="(devel)"`, which is the truth about it. `make image` passes them from
`git describe`, so a local image says `-dirty` when the tree was.

---

## First-time and one-off setup

**The package starts out private.** GHCR creates it that way on the first push,
regardless of the repository's visibility, and an anonymous `docker pull` gets a
404 that reads like a typo. Fix it once: the repository's Packages page →
`anteroom` → Package settings → Change visibility → Public. Nothing in the
workflow can do this, and every subsequent push inherits the setting.

## Which repository publishes

This one. The workflow derives the image name from
`github.repository_owner` rather than hardcoding it, so
`ghcr.io/radiustechsystems/anteroom` — the name the site advertises — falls out
of running it here, and the same file stays correct in a fork or a development
mirror without an edit.

That is the whole reason for the derivation, and the reason it matters. GHCR
packages belong to an owner, and the default `GITHUB_TOKEN` can only write
packages under the running repository's owner. Consequences worth stating plainly:

- **A tag pushed in a development repository publishes under that repository's
  owner**, not the advertised name, and no redirect connects the two. Cut
  releases from the public repository. If a development repository genuinely has
  to publish to the public name, that needs credentials rather than an edit: set
  the repository variable `ANTEROOM_IMAGE` to the full image path and the secret
  `GHCR_TOKEN` to a PAT with `write:packages` on the target owner. The workflow
  prefers both when present; unset them the moment they stop being needed.
- **The cosign identity below names the repository that signed the image.**
  Signatures are bound to a workflow in a repository — that is what makes them
  worth checking — so a release cut somewhere else verifies against a different
  identity, and the verification command has to say which.

The module path is not part of this. The `-X` flags that stamp the version are
assembled from `go list -m` in the `Dockerfile` rather than written out, because
a wrong `-X` path is not a build error: the linker ignores an override it cannot
resolve and the gate reports the toolchain's own guesses, with nothing in the
build log to say the stamp was dropped. Whatever `go.mod` says, the stamp lands.
