# kyverno-policies

![Version: 0.2.0](https://img.shields.io/badge/Version-0.2.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: latest](https://img.shields.io/badge/AppVersion-latest-informational?style=flat-square)

Kyverno ClusterPolicies that put an Anteroom proof-of-work gate in front of workloads by admission policy. Label a pod template and the gate is injected as a sidecar proxy; label a Service and its traffic is rewritten through the gate; label a namespace and the config and signing key the sidecar mounts are provisioned into it, optionally with a NetworkPolicy fencing the application's own port. Removing a label undoes what adding it did. The application manifests never mention Anteroom.

This chart installs policy, not workloads: four [Kyverno](https://kyverno.io)
ClusterPolicies by default (a fifth, the NetworkPolicy fence, is opt-in) and
the ClusterRole they need. Nothing runs until a resource opts in with the
labels below. The working end-to-end setup — demo app, kind bootstrap script,
verification steps — is [`examples/kyverno/`](../../examples/kyverno/) in this
repository.

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
| `anteroom.radiustech.xyz/original-ports` | Service | **Written by the chart, not by you.** The Service's `spec.ports` as they last arrived un-rewritten, recorded so that removing the `proxied` label can put them back. Do not hand-edit it; deleting it costs you the automatic revert and nothing else. Disable with `policies.restoreService=false`. |

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
| `route-service-through-anteroom` | Services | Sets every port's `targetPort` to the named port `anteroom`, after recording the originals in an annotation so that removing the label restores them. Every port — a Service that also exposes a side channel (gRPC, metrics) should not carry the label; split the HTTP port into its own labeled Service. |
| `generate-anteroom-config` | Namespaces | Generates the ConfigMap holding `gateConfig` (synchronized: chart upgrades roll config out to every namespace; hand-edits to copies are reverted) and clones the HMAC Secret from `hmacSecret.sourceNamespace`. |
| `generate-anteroom-networkpolicy` | Namespaces | **Opt-in** (`policies.networkPolicy=true`). Generates a NetworkPolicy admitting only TCP 8080 to gated pods, so the application's own port stops answering on the pod IP. Read the section below before enabling it. |
| `audit-anteroom-drift` | Pods | Audit only. Reports pods that carry the inject label but no gate container — the state left by a pod admitted while injection was not running, which is invisible from outside and unreachable through an already-rewritten Service. |

One boundary that stays where it is: the gate's admin listener (`/metrics`,
`/stats`, `/healthz`) binds the pod's loopback, reachable via `kubectl
port-forward` but not from the cluster network. Widening it is an edit to
`gateConfig`, made knowing metrics reveal traffic volumes.

## Closing the side door

Rewriting the Service moves *Service* traffic behind the gate. It does nothing
about the pod IP, which keeps answering on the application's own port to
anything that can route to it — the Kubernetes equivalent of an app container
that still publishes its own port. Whether that matters depends on who shares
your cluster.

The fence is `policies.networkPolicy=true`, which generates one NetworkPolicy
per opted-in namespace:

```yaml
podSelector:
  matchLabels:
    anteroom.radiustech.xyz/inject: enabled   # the same pods that get a gate
policyTypes: [Ingress]                        # egress untouched, deliberately
ingress:
  - ports: [{ port: 8080, protocol: TCP }]    # and nothing else
```

Selecting a pod with an ingress rule denies every inbound connection the rule
does not name, so the application's port stops answering without being
mentioned. `policyTypes` names Ingress alone on purpose: adding Egress would
deny all outbound traffic from gated pods the moment it landed, DNS included.

**It is off by default because it is the one resource here whose failure mode
is not visible in the object it creates.** Two things to establish on your own
CNI first:

1. **Does your CNI implement NetworkPolicy at all?** On one that does not —
   kind's default `kindnetd` among them — the object applies cleanly and
   enforces nothing. It looks installed and fences nothing.
2. **Are kubelet probes exempt from it?** The application container's probes
   target the application's port, which is precisely what this fences. Some
   plugins exempt node-sourced traffic; where yours does not, this policy
   kills healthy pods.

For case 2, admit the node CIDR through `networkPolicy.extraIngress` — there is
no portable "from the node" selector, so name the range and omit `ports`, since
the kubelet dials whatever port each workload uses:

```yaml
networkPolicy:
  extraIngress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/16    # kubectl get nodes -o wide, INTERNAL-IP
```

Verify the fence rather than trusting it, from a pod that should be refused:

```sh
kubectl -n hello run probe --rm -it --restart=Never --image=curlimages/curl \
  -- -sS --max-time 5 http://<pod-ip>:3000/
# a timeout is the pass. A 200 means the policy is not being enforced.
```

## Opting out, and what cleans itself up

Removing the opt-in metadata is the reverse of adding it, and most of it is
handled — but not all, and the parts that are not are worth knowing before you
start pulling labels off in production.

| Remove | What happens | Left to do |
| --- | --- | --- |
| Namespace `inject` label | The generated ConfigMap and NetworkPolicy and the cloned Secret are **deleted**. A synchronized generate rule watches its trigger, and a trigger that stops matching is treated exactly like a deleted one. | Nothing. |
| Service `proxied` label | The recorded ports are **restored** and the bookkeeping annotation dropped, on the same request that removes the label. | Nothing. |
| Pod template `inject` label | New pods come up with no gate. Running pods keep theirs: a pod's container list is immutable after admission, so there is no mutation — by Kyverno or anyone — that can take a sidecar out of a running pod. | `kubectl rollout restart` the workload. |
| Pod template `upstream-port` annotation, label kept | The next pod is **refused** at admission with the message naming the annotation. Half-removing the opt-in is not a state you can reach by accident. | Remove the label too, or put the annotation back. |
| The ClusterPolicies (or the whole chart) | Generated-from-data downstreams — the ConfigMap and the NetworkPolicy — are **deleted in every namespace**. The cloned Secret is **retained**: Kyverno does not delete copies of a secret as a side effect. Nothing changes for running pods until they are rolled. | Set `orphanDownstreamOnPolicyDelete=true` first if you meant to keep the config. Roll the workloads. Remove the Service labels **before** the policies, or the restore rule will not be there to revert them. |

Order matters in exactly one place, and it is the last row: deleting the
policies while Services still carry `proxied: enabled` leaves those Services
targeting the port name `anteroom` with no policy left to revert them, so the
next ungated rollout blackholes. Take the Service labels off first and the
revert happens while the rule still exists.

Two things no policy can do, and both are by design rather than oversight.
Kyverno runs at admission, so it cannot un-inject a running pod — the sidecar
leaves with the pod. And visitors holding a renewal service worker retire it
themselves once the gate's endpoints stop answering; `/.anteroom/uninstall`
does it immediately.

## Checking the policies

`charts/kyverno-policies/tests/run.sh` evaluates every policy against fixtures
with [`kyverno apply`](https://kyverno.io/docs/kyverno-cli/) and diffs the
result against committed expectations — no cluster needed. `make helm-test` at
the repository root runs it, and CI runs it on every commit.

It checks the policies, not the network: that a NetworkPolicy comes out with
the right selector and ports is a different question from what a CNI does with
it, and only a real cluster answers the second.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| configMapName | string | `"anteroom-config"` | Name of the per-namespace ConfigMap the generate policy creates and the injected sidecar mounts at /etc/anteroom. |
| gateConfig | string | the fully commented `anteroom.toml` in values.yaml — read it there | The gate's whole configuration file, generated verbatim into every opted-in namespace as `anteroom.toml` and mounted over /etc/anteroom. This is the single place the fleet's gate policy lives: edits here roll out to every namespace on upgrade (and hand-edits to generated copies are reverted), though the gate reads the file at startup, so a change lands with a rollout. `upstream` is deliberately absent — the injection policy supplies it per pod as ANTEROOM_UPSTREAM. Unknown keys are a startup error; check spelling against anteroom.example.toml at the repository root. |
| hmacSecret.clone | bool | `true` | Clone the signing-key Secret into every opted-in namespace. One key cluster-wide is the simple default and what makes any two replicas of the same gate verify each other's passes; its cost is that every namespace holds the same secret. If namespaces are your isolation boundary, disable this and create per-namespace Secrets by hand. |
| hmacSecret.sourceName | string | `"anteroom"` | Name of the source Secret in `sourceNamespace`. |
| hmacSecret.sourceNamespace | string | `"anteroom-system"` | Namespace holding the source Secret. The chart never creates the key — mint it once with `openssl rand -base64 32`; a key in a values file or a chart is a published key. |
| image.pullPolicy | string | `"IfNotPresent"` | Deliberately IfNotPresent, not the Always a `latest` tag would default to: Always makes every pod start a registry round-trip and ignores images loaded directly onto nodes (`kind load`, air-gapped mirrors). With a pinned digest the two behave identically. |
| image.repository | string | `"ghcr.io/radiustechsystems/anteroom"` | Gate image injected into opted-in pods. |
| image.tag | string | `"latest"` | Tag or digest of the gate image. `latest` is right for trying this and wrong in front of a real site — a pod reschedule can change the gate. Pin a digest or a minor version in production (docs/docker.md, "Which tag"). |
| networkPolicy.extraIngress | list | `[]` | Ingress rules appended verbatim to the generated NetworkPolicy, whose own rule admits nothing but TCP 8080. This is where the kubelet-probe problem gets solved on a CNI that does not exempt node traffic: name the node CIDR in an `ipBlock` and omit `ports`, since there is no portable "from the node" selector and the kubelet dials whatever port each workload uses. The same list is how an in-cluster Prometheus reaches a widened `admin_listen`, or how a mesh sidecar keeps a side channel. Every entry widens the fence, so each one deserves a comment saying why. See "Closing the side door" in this chart's README for the worked example. |
| networkPolicy.name | string | `"only-through-anteroom"` | Name of the generated NetworkPolicy in each opted-in namespace. |
| orphanDownstreamOnPolicyDelete | bool | `false` | Keep generated resources when the policy or the whole chart is removed. Worth understanding before `helm uninstall`, because Kyverno's default is not symmetric: the ConfigMap and the NetworkPolicy are generated from data in the policy, so deleting the policy DELETES them in every namespace, while the HMAC Secret is a clone and clones are retained. Set this to true and the generated copies outlive the chart in every namespace — right when the chart is being replaced or moved rather than withdrawn, and wrong if you expect uninstall to leave nothing behind. |
| policies.auditDrift | bool | `true` | Create the Audit-mode policy that reports pods carrying the inject label but no gate container. That combination means a pod was admitted while injection was off or broken, and it is worth a report because it is invisible from the outside and blackholes any Service already rewritten to `anteroom`. Audit only — it never blocks admission — and it matches only opted-in pods, so it reports on nothing you did not label. |
| policies.generateConfig | bool | `true` | Create the generate rule that provisions the per-namespace ConfigMap holding `gateConfig` below. |
| policies.injectSidecar | bool | `true` | Create the pod-mutating policy that injects the gate sidecar. |
| policies.networkPolicy | bool | `false` | Create the NetworkPolicy that admits only the gate's port to gated pods, so nothing on the cluster network can reach the application container directly on the pod IP. **Off by default and read this first:** a NetworkPolicy is the one resource here whose failure mode is invisible in the object it creates. On a CNI that does not implement NetworkPolicy (kind's default kindnetd among them) it applies cleanly and fences nothing. On a CNI that does, whether the kubelet's probe traffic is exempt is a per-plugin answer — and the application container's probes target the very port this fences, so where they are not exempt this kills healthy pods. Verify both on your own CNI, then turn it on; use `networkPolicy.extraIngress` for the probe case. |
| policies.restoreService | bool | `true` | Record each labeled Service's original `spec.ports` in the annotation `anteroom.radiustech.xyz/original-ports` before rewriting it, and restore them when the `proxied` label is removed. Without this, removing the label leaves the Service targeting the port name `anteroom`, which blackholes it once the pods roll ungated — a mutation is stored, not overlaid, so nothing else can put the value back. The restore rule matches Services *without* the label, i.e. nearly all of them, which costs one extra rule evaluation per Service admission and no extra webhook traffic: Kyverno registers webhooks per kind and operation, so every Service create and update already reached it for the rewrite rule. The rule short-circuits on the missing annotation. |
| policies.routeService | bool | `true` | Create the Service-mutating policy that rewrites every port's targetPort to the gate's named port. |
| rbac.create | bool | `true` | Create the ClusterRole that aggregates ConfigMap/Secret permissions to Kyverno's admission and background controllers — plus NetworkPolicy permissions when `policies.networkPolicy` is on, and only then. Without it the generate policy is refused at apply time by Kyverno's policy-validation webhook, which names the missing permission. Secrets are the sensitive half of the grant: the background controller can then read and write Secrets in every namespace, which is inherent to cloning a key across namespaces. If that is too broad, disable `hmacSecret.clone`, distribute the key another way, and narrow this role. |
| secretName | string | `"anteroom"` | Name of the per-namespace Secret the sidecar reads ANTEROOM_HMAC_KEY from (key `hmac-key`). With `hmacSecret.clone` off, create a Secret with this name and key in every opted-in namespace yourself. |
| sidecar.resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}` | Compute for the injected gate: one binary proxying one app, so modest on purpose. The limit is memory only — a CPU limit would throttle the proxy path under the exact load the gate exists to absorb. |
| sidecar.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | The gate's image is distroless, non-root, and needs nothing; say so where the admission controller can hold it to that. |

## Regenerating this file

This README is generated by [helm-docs](https://github.com/norwoodj/helm-docs)
from `README.md.gotmpl` and the `# --` comments in `values.yaml`. Edit those,
then run `make helm-docs` at the repository root.

