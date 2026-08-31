# kyverno-policies

![Version: 0.2.1](https://img.shields.io/badge/Version-0.2.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: latest](https://img.shields.io/badge/AppVersion-latest-informational?style=flat-square)

Kyverno ClusterPolicies that put an Anteroom proof-of-work gate in front of workloads by admission policy. Label a pod template and the gate is injected as a sidecar proxy; label a Service and its traffic is rewritten through the gate; label a namespace and the config and signing key the sidecar mounts are provisioned into it. The application manifests never mention Anteroom.

This chart installs policy, not workloads: three [Kyverno](https://kyverno.io)
ClusterPolicies and the ClusterRole they need. Nothing runs until a resource
opts in with the labels below. The working end-to-end setup — demo app,
kind bootstrap script, verification steps — is
[`examples/kyverno/`](../../examples/kyverno/) in this repository.

## Prerequisites

- Kyverno 1.11+ installed ([their quick start](https://kyverno.io/docs/installation/)).
- The signing-key Secret, minted once, in the namespace the chart clones it
  from. The chart never creates the key — a key in a values file is a
  published key:

  ```sh
  kubectl create namespace anteroom-system
  kubectl -n anteroom-system create secret generic anteroom \
    --from-literal=hmac-key="$(openssl rand -base64 32)"
  ```

## Installing

```sh
helm install anteroom-policies ./charts/kyverno-policies
```

The policies are cluster-scoped singletons with fixed names: install this
chart once per cluster. If the install is refused with a Kyverno message
naming a missing ConfigMap/Secret permission, the ClusterRole this chart
ships had not finished aggregating into Kyverno's roles when the policy
arrived — aggregation is asynchronous — and re-running the same command a
moment later succeeds.

## The opt-in surface

Everything is explicit, and each resource asks for its own rewrite. These
keys are fixed — they are the chart's API.

### Labels

| Label | On | Meaning |
| --- | --- | --- |
| `anteroom.radiustech.xyz/inject: enabled` | Namespace | Generate the gate's ConfigMap into this namespace and clone the HMAC Secret into it. |
| `anteroom.radiustech.xyz/inject: enabled` | Pod template | Inject the gate as a sidecar proxy container into the pod. |
| `anteroom.radiustech.xyz/proxied: enabled` | Service | Rewrite every port's `targetPort` to the named port `anteroom`, routing the Service through the gate. |

### Annotations

| Annotation | On | Meaning |
| --- | --- | --- |
| `anteroom.radiustech.xyz/upstream-port: "3000"` | Pod template | The port the application container listens on; the gate proxies to `127.0.0.1:<port>`. **Required** wherever the inject label is present — a labeled pod without it is refused at admission rather than given a guessed port. |

A workload opts in with three lines and never mentions Anteroom otherwise:

```yaml
# Deployment pod template
metadata:
  labels:
    anteroom.radiustech.xyz/inject: enabled
  annotations:
    anteroom.radiustech.xyz/upstream-port: "3000"
---
# Service
metadata:
  labels:
    anteroom.radiustech.xyz/proxied: enabled
```

The namespace holding the workload carries the inject label too:

```yaml
metadata:
  labels:
    anteroom.radiustech.xyz/inject: enabled
```

After admission the path is:

```
client → Service :80 → targetPort "anteroom" → gate :8080 → 127.0.0.1:<upstream-port> → app
```

The Service does not inherit the pods' opt-in on purpose: at admission a
Service is just a selector, so Kyverno cannot know whether the pods it will
match carry a gate, and rewriting on a guess would blackhole Services whose
pods were never injected.

## What the policies do

| Policy | Acts on | Effect |
| --- | --- | --- |
| `inject-anteroom-sidecar` | Pods | Adds the gate container (port 8080, named `anteroom`), proxying to `127.0.0.1:<upstream-port>`, with the config ConfigMap mounted at `/etc/anteroom` and `ANTEROOM_HMAC_KEY` from the namespace's Secret. Readiness on `/.anteroom/healthz` sequences traffic: an unready gate keeps the pod out of the Service. |
| `route-service-through-anteroom` | Services | Sets every port's `targetPort` to the named port `anteroom`. Every port — a Service that also exposes a side channel (gRPC, metrics) should not carry the label; split the HTTP port into its own labeled Service. |
| `generate-anteroom-config` | Namespaces | Generates the ConfigMap holding `gateConfig` (synchronized: chart upgrades roll config out to every namespace; hand-edits to copies are reverted), clones the HMAC Secret from `hmacSecret.sourceNamespace`, and — with `admin.networkPolicy.enabled` — generates the NetworkPolicy fencing the exposed admin port. |

Two boundaries worth knowing about, documented with fixes in the
[example's README](../../examples/kyverno/README.md): the Service rewrite
moves *Service* traffic behind the gate, but any pod can still dial the app's
port on the pod IP directly (the fence is a NetworkPolicy admitting only port
8080); and the gate's admin listener (`/metrics`, `/stats`, `/activity`,
`/healthz`) binds the pod's loopback, reachable via `kubectl port-forward`
but not from the cluster network.

## Scraping the fleet

The loopback default is right until something in the cluster needs to read
`/metrics` — a Prometheus, or
[anteroom-stats](https://github.com/radiustechsystems/anteroom-stats) in its
Kubernetes mode, which discovers gates by the same
`anteroom.radiustech.xyz/inject=enabled` label this chart already keys on.
`admin.expose` moves the listener onto the pod network and names the port
`anteroom-admin` so a scraper can resolve it without knowing the number:

```sh
helm upgrade --install anteroom-policies ./charts/kyverno-policies \
  --set admin.expose=true \
  --set admin.networkPolicy.enabled=true
```

It is a real trade, not a formality. The listener is unauthenticated and
reports traffic volumes and — wherever `gateConfig` grows an `[activity]`
section — visitor IP addresses; exposing it without the NetworkPolicy hands
both to every pod in the cluster. And the NetworkPolicy is not free either:
it is deny-by-default for the pods it selects, so it closes the direct route
to the application's own port and, on some CNIs, blocks kubelet probes. Read
`admin.networkPolicy.enabled`'s description before turning it on, and verify
probes survive on your CNI.

Existing pods keep the loopback binding until they restart: the env var is
set at admission, so the change lands with a rollout
(`kubectl -n <ns> rollout restart deploy/<name>`).

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| admin.expose | bool | `false` | Bind the operator listener to the pod network so an in-cluster scraper can reach it, by setting ANTEROOM_ADMIN_LISTEN on the injected sidecar (an environment variable overrides `admin_listen` in the mounted TOML, which is why `gateConfig` needs no edit and stays safe to override). OFF by default and deliberately so: the listener is UNAUTHENTICATED — reachability is its entire access control — and it reports traffic volumes and, with an `[activity]` section configured, visitor IP addresses. Turning this on without `networkPolicy` below publishes both to every pod in the cluster. |
| admin.networkPolicy.collectorNamespaceSelector | object | `{"kubernetes.io/metadata.name":"anteroom-system"}` | Labels identifying the namespace the collector runs in. Empty means "the same namespace as the gated pods", which is almost never what a cluster-wide collector wants. |
| admin.networkPolicy.collectorSelector | object | `{"app.kubernetes.io/name":"anteroom-stats"}` | Labels identifying the collector's pods, admitted to `admin.port`. |
| admin.networkPolicy.enabled | bool | `false` | Generate a NetworkPolicy into every opted-in namespace admitting the admin port only from the collector selected below. Requires a CNI that enforces NetworkPolicy, and READ THE NEXT SENTENCE: a NetworkPolicy that selects a pod denies every ingress it does not admit, so this also closes the direct route to the application's own port — the side door the example README describes — and on some CNIs it blocks kubelet probe traffic, which kills healthy pods. Verify probes survive on your CNI before enabling it, and use `extraIngress` for anything else that must still reach these pods. |
| admin.networkPolicy.extraIngress | list | `[]` | Extra ingress rules appended verbatim to the generated policy, for whatever else must still reach these pods once the deny-by-default of a NetworkPolicy applies — a second scraper, an in-cluster health checker, or the application's own port for a client that legitimately bypasses the gate. |
| admin.port | int | `8090` | Port for the exposed listener. Injected as a container port named `anteroom-admin`, which is how a scraper finds it without knowing the number — the same trick the traffic port's `anteroom` name plays for the Service policy. Must not collide with the gate's 8080 or the app's port. |
| configMapName | string | `"anteroom-config"` | Name of the per-namespace ConfigMap the generate policy creates and the injected sidecar mounts at /etc/anteroom. |
| gateConfig | string | the fully commented `anteroom.toml` in values.yaml — read it there | The gate's whole configuration file, generated verbatim into every opted-in namespace as `anteroom.toml` and mounted over /etc/anteroom. This is the single place the fleet's gate policy lives: edits here roll out to every namespace on upgrade (and hand-edits to generated copies are reverted), though the gate reads the file at startup, so a change lands with a rollout. `upstream` is deliberately absent — the injection policy supplies it per pod as ANTEROOM_UPSTREAM. Unknown keys are a startup error; check spelling against anteroom.example.toml at the repository root. |
| hmacSecret.clone | bool | `true` | Clone the signing-key Secret into every opted-in namespace. One key cluster-wide is the simple default and what makes any two replicas of the same gate verify each other's passes; its cost is that every namespace holds the same secret. If namespaces are your isolation boundary, disable this and create per-namespace Secrets by hand. |
| hmacSecret.sourceName | string | `"anteroom"` | Name of the source Secret in `sourceNamespace`. |
| hmacSecret.sourceNamespace | string | `"anteroom-system"` | Namespace holding the source Secret. The chart never creates the key — mint it once with `openssl rand -base64 32`; a key in a values file or a chart is a published key. |
| image.pullPolicy | string | `"IfNotPresent"` | Deliberately IfNotPresent, not the Always a `latest` tag would default to: Always makes every pod start a registry round-trip and ignores images loaded directly onto nodes (`kind load`, air-gapped mirrors). With a pinned digest the two behave identically. |
| image.repository | string | `"ghcr.io/radiustechsystems/anteroom"` | Gate image injected into opted-in pods. |
| image.tag | string | `"latest"` | Tag or digest of the gate image. `latest` is right for trying this and wrong in front of a real site — a pod reschedule can change the gate. Pin a digest or a minor version in production (docs/docker.md, "Which tag"). |
| policies.generateConfig | bool | `true` | Create the generate rule that provisions the per-namespace ConfigMap holding `gateConfig` below. |
| policies.injectSidecar | bool | `true` | Create the pod-mutating policy that injects the gate sidecar. |
| policies.routeService | bool | `true` | Create the Service-mutating policy that rewrites every port's targetPort to the gate's named port. |
| rbac.create | bool | `true` | Create the ClusterRole that aggregates ConfigMap/Secret permissions (and, with `admin.networkPolicy.enabled`, NetworkPolicy permissions) to Kyverno's admission and background controllers. Without it the generate policy is refused at apply time by Kyverno's policy-validation webhook. Secrets are the sensitive half of the grant: the background controller can then read and write Secrets in every namespace, which is inherent to cloning a key across namespaces. If that is too broad, disable `hmacSecret.clone`, distribute the key another way, and narrow this role. |
| secretName | string | `"anteroom"` | Name of the per-namespace Secret the sidecar reads ANTEROOM_HMAC_KEY from (key `hmac-key`). With `hmacSecret.clone` off, create a Secret with this name and key in every opted-in namespace yourself. |
| sidecar.resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}` | Compute for the injected gate: one binary proxying one app, so modest on purpose. The limit is memory only — a CPU limit would throttle the proxy path under the exact load the gate exists to absorb. |
| sidecar.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | The gate's image is distroless, non-root, and needs nothing; say so where the admission controller can hold it to that. |

## Regenerating this file

This README is generated by [helm-docs](https://github.com/norwoodj/helm-docs)
from `README.md.gotmpl` and the `# --` comments in `values.yaml`. Edit those,
then run `make helm-docs` at the repository root.

