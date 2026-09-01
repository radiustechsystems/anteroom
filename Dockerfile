# Anteroom container image.
#
# Two properties are deliberate and load-bearing, and both are asserted by the
# Tier 0 acceptance tests:
#
#   1. The runtime stage has no shell, no package manager, and no libc to speak
#      of. A gate sits in the request path of someone else's site; the smallest
#      thing that can serve is the right thing to ship. This is also why the
#      health check is `anteroom healthcheck` rather than a curl invocation —
#      there is nothing here for a shell-form HEALTHCHECK to run.
#   2. It runs as a non-root UID and needs no capabilities. `listen` defaults to
#      :8080 for exactly this reason: publish it as `-p 80:8080` and let the
#      daemon own the privileged half.

# --- build ------------------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependency layer first: go.mod/go.sum change far less often than the source,
# so an ordinary code edit does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS/TARGETARCH are supplied by buildx for each platform in a multi-arch
# build; they default to the build host under a plain `docker build`.
ARG TARGETOS
ARG TARGETARCH

# The commit, for anteroom_build_info. The toolchain would stamp this itself,
# but .git is excluded from the build context on purpose, so it has nothing to
# read and the running gate could never say which code it is. Pass it in:
#
#   docker build --build-arg VCS_REF=$(git rev-parse HEAD) .
#
# Leaving it unset is not an error — the metric reports revision="unknown",
# which is the truth about a build that was handed no revision.
ARG VCS_REF

# The version, for the same metric and for the same reason: debug.BuildInfo
# reports Main.Version as "(devel)" for anything not installed as
# module@version, which is every image ever built here. A published image is the
# one build that genuinely has a version — the tag it was released under — and
# without this it would be the build least able to say so.
#
#   docker build --build-arg VERSION=v1.2.3 .
#
# Unset is not an error: the metric keeps reporting "(devel)", which is the
# truth about a build nobody released.
ARG VERSION

# CGO_ENABLED=0 is what makes the binary static enough for a distroless base.
# -trimpath keeps build paths out of the binary (reproducibility, and it is one
# less thing leaked by a panic); -s -w drop the symbol table and DWARF, which is
# roughly a third of the size and costs only a symbolized stack trace.
#
# The two -X paths are assembled from `go list -m` rather than written out. A
# wrong -X path is not a build error — the linker ignores an override it cannot
# resolve, silently, and the gate then reports the toolchain's own guesses while
# the build log says nothing. That is the worst failure mode available here,
# because the whole point of these two variables is to be believed.
RUN MOD="$(go list -m)" && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w \
        -X ${MOD}/internal/metrics.Revision=${VCS_REF} \
        -X ${MOD}/internal/metrics.Version=${VERSION}" \
      -o /out/anteroom ./cmd/anteroom

# Seed the payment-state mount point with ownership matching the runtime user.
# A named Docker volume inherits this ownership when it is first attached.
RUN mkdir -p /out/state

# --- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/anteroom /anteroom
COPY --from=build --chown=65532:65532 /out/state /var/lib/anteroom

# A default config so the image is usable with environment variables alone:
# config.Load treats a *named* missing file as an error (correctly — a typo'd
# --config path must not silently fall back to defaults), so an image with no
# config at all could never start from `-e ANTEROOM_UPSTREAM=…`. This file
# supplies every default and leaves `upstream` to the environment. Mounting your
# own over /etc/anteroom/anteroom.toml replaces it wholesale.
COPY docker/anteroom.default.toml /etc/anteroom/anteroom.toml

EXPOSE 8080

# The binary probes itself: exec form, no shell, no curl in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=2s --retries=3 \
    CMD ["/anteroom", "healthcheck", "--config", "/etc/anteroom/anteroom.toml"]

# 65532:65532 (nonroot) comes from the base image; restated so it survives a
# base change and so `docker inspect` shows it without a lookup.
USER 65532:65532

ENTRYPOINT ["/anteroom"]
CMD ["serve", "--config", "/etc/anteroom/anteroom.toml"]
