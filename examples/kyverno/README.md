# Anteroom by admission policy: Kyverno sidecar injection

The Compose sidecar in [`../anteroomized/`](../anteroomized/) is one gate
wired to one app by hand. This example is the same topology run as cluster
policy: label a workload and [Kyverno](https://kyverno.io) injects the gate,
rewires the Service through it, and provisions the config and signing key the
sidecar mounts — the application manifests never mention Anteroom at all.

The policies themselves live in the
[`charts/kyverno-policies`](../../charts/kyverno-policies/) Helm chart at the
repository root — its README documents the opt-in labels and annotations and
every value. Five policies, one job each:

| Policy | Acts on | What it does |
| --- | --- | --- |
| [`inject-anteroom-sidecar`](../../charts/kyverno-policies/templates/clusterpolicy-inject-sidecar.yaml) | Pods | injects the gate as a sidecar proxy container, forwarding to `127.0.0.1:<upstream-port>` |
| [`route-service-through-anteroom`](../../charts/kyverno-policies/templates/clusterpolicy-route-service.yaml) | Services | rewrites every `targetPort` to the named port `anteroom`, putting the gate in the traffic path — and restores the originals if the label is removed |
| [`generate-anteroom-config`](../../charts/kyverno-policies/templates/clusterpolicy-generate-config.yaml) | Namespaces | generates the `anteroom-config` ConfigMap and clones the `anteroom` HMAC Secret into the namespace |
| [`generate-anteroom-networkpolicy`](../../charts/kyverno-policies/templates/clusterpolicy-generate-networkpolicy.yaml) | Namespaces | **opt-in** — fences gated pods so only the gate's port answers on the pod IP |
| [`audit-anteroom-drift`](../../charts/kyverno-policies/templates/clusterpolicy-audit-drift.yaml) | Pods | reports pods that opted in but carry no gate, the one failure that is invisible from outside |

Plus the chart's [`rbac.yaml`](../../charts/kyverno-policies/templates/rbac.yaml),
the grant Kyverno's controllers need for what the generate policies manage.
This directory holds what the chart deliberately leaves out:
[`manifests/demo/`](manifests/demo/), a two-replica `hello-app` behind the
gate, and [`scripts/kind-demo.sh`](scripts/kind-demo.sh), which stands the
whole thing up on a local [kind](https://kind.sigs.k8s.io) cluster and leaves
you with port-forwards to the gate, its metrics, and the ungated upstream.

## The opt-in surface

Everything is explicit, and each resource asks for its own rewrite:

| Where | Metadata | Meaning |
| --- | --- | --- |
| Namespace | label `anteroom.radiustech.xyz/inject: enabled` | generate the ConfigMap, clone the key |
| Pod template | label `anteroom.radiustech.xyz/inject: enabled` | inject the sidecar |
| Pod template | annotation `anteroom.radiustech.xyz/upstream-port: "3000"` | where the app listens; **required** with the label — a missing port is an admission error, not a guessed default |
| Service | label `anteroom.radiustech.xyz/proxied: enabled` | rewrite `targetPort` to the gate |

One more piece of metadata appears that you do not write: the policy records a
labeled Service's original `spec.ports` in the annotation
`anteroom.radiustech.xyz/original-ports` before overwriting them, which is what
lets removing the label put them back. See
[Removing it](#removing-it) below.

The Service does not inherit the pods' opt-in on purpose. At admission a
Service is just a selector; Kyverno cannot know which pods it will match or
whether they carry a gate, and rewriting on a guess would blackhole Services
whose pods were never injected. Two labels keep both rewrites legible in the
manifests that asked for them.

After admission the path is:

```
client → Service :80 → targetPort "anteroom" → gate :8080 → 127.0.0.1:3000 → app
```

The named port is the trick that decouples the policies: the Service rewrite
targets the *name*, the injection carries the name on `containerPort: 8080`,
and neither policy needs the other's numbers.

## Try it

The script does everything on a local kind cluster — creates it, installs
Kyverno, builds the gate and `hello-app` from this checkout and loads them,
mints the signing key, installs the policies chart, applies the demo,
verifies the Service was rewritten, and starts port-forwards (requires
docker, kind, kubectl, helm, openssl):

```sh
./scripts/kind-demo.sh
```

It ends with three port-forwards running and says so:

| Local | What it reaches |
| --- | --- |
| `http://localhost:8080` | the gated site: Service → gate → app. Browse it for the wait page and the ~1 s puzzle. |
| `http://localhost:8090/metrics` | the sidecar's admin listener (`/metrics`, `/stats`, `/healthz`), bound to the pod's loopback and reachable only this way |
| `http://localhost:3000` | `hello-app` directly, bypassing the gate — the cluster-internal side door made visible |

Ctrl-C stops the forwards and leaves the cluster;
`kind delete cluster --name anteroom-demo` removes it. The script is
idempotent — re-running skips whatever already exists (including the key: a
rotated key would wall every visitor holding a pass) and returns to the
port-forwards.

### Or by hand

Any cluster with Kyverno 1.11+
([their quick start](https://kyverno.io/docs/installation/)) works. Mint the
deployment key once, into the namespace the generate policy clones from —
keep it out of manifests and repositories, a committed key is a published
key:

```sh
kubectl create namespace anteroom-system
kubectl -n anteroom-system create secret generic anteroom \
  --from-literal=hmac-key="$(openssl rand -base64 32)"
```

Install the policies chart, then apply the demo (on kind, first
`docker build -t hello-app:local ../hello-app && kind load docker-image hello-app:local`):

```sh
helm install anteroom-policies ../../charts/kyverno-policies -n kyverno
kubectl apply -f manifests/demo/
```

If the install is refused with a Kyverno message naming a missing
Secret/ConfigMap permission, the chart's ClusterRole had not finished
aggregating into Kyverno's roles when the policy arrived — aggregation is
asynchronous. Re-run the same command a moment later (as
`helm upgrade --install`, which also recovers the failed release).

## Check that the gate is actually in the path

The Compose example's rule — verify the topology rather than trusting it —
translates directly:

```sh
# The pod runs two containers, the app and the injected gate:
kubectl -n hello get pods
# NAME                        READY   STATUS    RESTARTS
# hello-app-xxxxxxxxx-xxxxx   2/2     Running   0

# The Service was rewritten at admission:
kubectl -n hello get svc hello-app -o jsonpath='{.spec.ports[0].targetPort}'
# anteroom

# The namespace received its config and key:
kubectl -n hello get configmap anteroom-config secret anteroom

# Traffic through the Service meets the gate, not the app: a curl with no
# pass gets the machine-readable refusal, not hello-app's HTML.
kubectl -n hello run probe --rm -it --restart=Never --image=curlimages/curl \
  -- -si http://hello-app.hello.svc/ | head -1
# HTTP/1.1 403 Forbidden
```

Then see it as a visitor — the script's port-forward is already running, or
by hand:

```sh
kubectl -n hello port-forward svc/hello-app 8080:80
# browse http://localhost:8080
```

Port-forwarding lands on `localhost`, which is a secure context, so the
puzzle runs and the wait page resolves into the app in about a second.

Reload a few times: the demo runs two replicas, and not being asked to solve
again on every other request is the observable proof that both gates hold the
same key. If visitors *do* re-solve constantly, the keys differ — check that
both pods mount the same generated Secret and that nothing supplies a
file-based `[[hmac_keys]]` to one of them.

## What the policies decide, and why

**An ordinary container, ordered by readiness.** The gate is a second entry in
`containers`, running as a long-lived proxy beside the app, and its readiness
probe is what sequences traffic: until the gate answers `/.anteroom/healthz`
the pod is not Ready and the Service sends it nothing, so there is no window
where traffic routes to a pod whose gate is absent. On Kubernetes 1.29+ the
same spec also works under `initContainers` with `restartPolicy: Always` — the
"native sidecar" pattern, which still runs for the pod's whole life but adds
kubelet-guaranteed start-before-app and stop-after-app ordering, useful if the
app itself dials out through a proxy at startup. Anteroom doesn't need that,
so the policy stays with the portable shape.

**Pods are mutated, not Deployments.** The policy sets
`pod-policies.kyverno.io/autogen-controllers: none`, so the Deployment in git
stays byte-identical to the Deployment in the cluster and GitOps controllers
have nothing to fight. The cost is that the sidecar is only visible on the
Pod — which is where you debug it anyway.

**The ConfigMap is generated as data, the Secret as a clone.** Policy — TTLs,
difficulty, bypass paths — belongs in one reviewable place, so the TOML lives
in the generate policy itself and `synchronize: true` rolls edits out to every
namespace (and reverts hand-edits to the copies). A key must never live in a
policy file, so it is minted once by you and cloned from `anteroom-system`.
Config edits are synced into running pods within a minute but the gate reads
its TOML at startup, so a policy change lands with a rollout:
`kubectl -n hello rollout restart deploy/hello-app`.

**One key cluster-wide is a default, not a law.** The clone gives every
namespace the same key, which is exactly right for replicas of one site and
too much sharing if namespaces are your isolation boundary. In that case drop
the clone rule and create per-namespace Secrets by hand — injection only
requires a Secret named `anteroom` with key `hmac-key`.

**The admin listener stays on the pod's loopback by default.** The generated
config sets `admin_listen = "127.0.0.1:8090"`, so `/metrics`, `/stats`, and
`/healthz` exist but nothing on the cluster network can reach them — the
listener is unauthenticated, and reachability is its only access control.
`kubectl port-forward` still works because it dials localhost inside the
pod's own network namespace, which is exactly the seam the script's metrics
forward uses. Widening it is one chart value, and the next section is about
what that costs.

**Probes keep working, and that is not a bypass hole.** The kubelet dials the
app's `containerPort` from inside the node, never through the Service, so app
probes need no `[bypass]` entry and the gate never sees them.

## Scraping the whole fleet

`kubectl port-forward` reaches one pod's metrics, which is the right tool for
debugging one pod and useless for the question a cluster actually raises:
what is the fleet doing, and is one replica behaving differently from its
siblings. Two chart values answer it:

```sh
helm upgrade --install anteroom-policies ../../charts/kyverno-policies -n kyverno \
  --set admin.expose=true \
  --set admin.networkPolicy.enabled=true
kubectl -n hello rollout restart deploy/hello-app   # the env var lands at admission
```

`admin.expose` sets `ANTEROOM_ADMIN_LISTEN=":8090"` on the injected sidecar —
an environment variable beats the mounted TOML, which is why `gateConfig`
keeps its loopback default and stays safe to override wholesale — and adds a
container port named `anteroom-admin`. The name is the same trick the traffic
port plays for the Service policy: a scraper resolves the name and never
needs to know the number, and a gate that does *not* carry the port is
visibly one whose operator did not opt into being scraped.

Anything that speaks Prometheus can then discover the pods by the label the
injection policy already keys on. So can
[anteroom-stats](https://github.com/radiustechsystems/anteroom-stats), whose
Kubernetes mode is built for exactly this shape — it lists pods matching
`anteroom.radiustech.xyz/inject=enabled`, polls each one's `/stats`, and
charts either the fleet as one number or any single replica on its own:

```sh
STATS_MODE=kubernetes
KUBE_LABEL_SELECTOR=anteroom.radiustech.xyz/inject=enabled
```

**What this costs.** The listener is unauthenticated by design, and it
reports traffic volumes and — wherever `gateConfig` grows an `[activity]`
section — visitor IP addresses. On loopback that does not matter; on the pod
network it means every pod in the cluster can read both. That is what
`admin.networkPolicy.enabled` is for: it generates a NetworkPolicy into each
opted-in namespace admitting `:8090` only from the collector's pods.

Read that value's description before enabling it. A NetworkPolicy is
deny-by-default for the pods it selects, so the generated one decides *all*
ingress to gated pods, not just the admin port. Two consequences: it closes
the side door below — deliberately, and admit anything you still need through
`admin.networkPolicy.extraIngress` — and on CNIs that do not exempt kubelet
probe traffic it blocks the probes, which kills healthy pods. Verify probes
survive on your CNI first; the warning under the side door applies here with
the same force, because it is the same mechanism.

## The side door, and the two traps

**Any pod can still dial the app directly.** Rewriting the Service moves
*Service* traffic behind the gate, but the pod IP answers on `:3000` to
anyone in the cluster — the Kubernetes equivalent of the Compose app that
still publishes its own port. Whether that matters depends on who shares your
cluster. The fence is a chart value:

```sh
helm upgrade --install anteroom-policies ../../charts/kyverno-policies -n kyverno \
  --set admin.networkPolicy.enabled=true
```

which generates one NetworkPolicy per opted-in namespace, selecting the same
pods the injection policy selects and admitting TCP 8080 and nothing else.
Ingress only — naming Egress would take DNS out from under every gated pod.
The switch lives under `admin.` because fencing an exposed `/metrics` is the
job it was added for, but it needs no `admin.expose`: a NetworkPolicy is
deny-by-default for the pods it selects, so the same object closes the side
door whether or not the admin listener is on the pod network.

**It is off by default, and on kind it cannot be demonstrated at all.** This
is the one resource in the chart whose failure mode is invisible in the object
it creates, in two different directions:

- kind's default CNI, `kindnetd`, does not implement NetworkPolicy. The object
  applies without error, `kubectl get networkpolicy` shows it, and the ungated
  port-forward at `localhost:3000` keeps working — because nothing is
  enforcing it. That is why the demo script leaves it off: a demo that appears
  to fence and does not is worse than one that admits the gap.
- Where a CNI *does* enforce it, whether kubelet probe traffic is exempt is a
  per-plugin, per-configuration answer. The app container's probes target
  `:3000`, precisely the port this fences, so on a plugin that does not exempt
  node-sourced traffic this policy kills healthy pods. Admit the node CIDR
  through `admin.networkPolicy.extraIngress` — the chart README's
  ["Closing the side door"](../../charts/kyverno-policies/README.md#closing-the-side-door)
  has the worked example.

So: try it on a cluster with Calico or Cilium, verify from a pod that should be
refused rather than trusting the object, and check that pods stay Ready.

```sh
# On kind this returns hello-app's HTML whether or not the policy exists,
# which is the point being made above.
kubectl -n hello run probe --rm -it --restart=Never --image=curlimages/curl \
  -- -sS --max-time 5 "http://$(kubectl -n hello get pod -l app=hello-app \
     -o jsonpath='{.items[0].status.podIP}'):3000/" | head -1
# a timeout is the pass; a 200 means nothing is enforcing the fence
```

**Trap 1 (no secure context) applies with full force.** The puzzle needs
WebCrypto and renewal needs a service worker; both require HTTPS or
`localhost`. A NodePort browsed at `http://10.x.y.z` walls every visitor
permanently. Production means TLS at your Ingress; the generated config's
`allow_insecure_context` comment covers the LAN-only fallback and its cost.

**Trap 2 (`trusted_proxies`) moves to the Ingress.** Inside the cluster
nothing sets `X-Forwarded-For`, so the generated default of `[]` is correct
and trusting anyone would let clients claim arbitrary addresses. Put an
ingress controller in front and the situation inverts: its range — usually the
pod CIDR — must be listed, or the pass cookie quietly loses its `Secure` flag
and the app sees the ingress's address instead of the visitor's. Both traps
are [`docs/docker.md`](../../docs/docker.md)'s, in Kubernetes clothing.

## What this example leaves out

**Payments.** The x402 door needs a writable state volume, and its bbolt
ledger coordinates only processes on one node — a single payment-enabled
replica by design ([`docs/docker.md`](../../docs/docker.md#kubernetes-sidecar)).
Auto-injecting identical replicas is the opposite shape, so this example is
the free gate only. A paid deployment wants a deliberate, hand-written
StatefulSet, not a policy.

**Custom wait pages.** Add a `pages` key to the generated ConfigMap holding
`header.html` and `footer.html`, mount it at `/etc/anteroom/pages`, and set
`pages = "/etc/anteroom/pages"` in the TOML. Both files must exist or the gate
refuses to start; the kubelet syncs edits into pods within a minute and the
gate re-reads them per challenge, so wait-page copy — unlike the TOML — needs
no rollout.

## Removing it

Remove the three labels and roll the workloads:

```sh
kubectl -n hello label svc hello-app anteroom.radiustech.xyz/proxied-
kubectl -n hello patch deploy hello-app --type=json -p='[
  {"op": "remove", "path": "/spec/template/metadata/labels/anteroom.radiustech.xyz~1inject"},
  {"op": "remove", "path": "/spec/template/metadata/annotations/anteroom.radiustech.xyz~1upstream-port"}
]'
kubectl label namespace hello anteroom.radiustech.xyz/inject-
```

Most of the cleanup is Kyverno's, and it is worth knowing which parts:

- **The Service reverts on the same request that removes the label.** Its
  original `spec.ports` were recorded in the annotation
  `anteroom.radiustech.xyz/original-ports` when they were first rewritten, so
  the restore rule has something to put back — which matters because a
  mutation is *stored*, not overlaid, and without the record nothing could
  reconstruct a `targetPort` that admission overwrote.
- **The namespace's generated resources are deleted** when its label goes: the
  ConfigMap, the cloned Secret, and the NetworkPolicy if you enabled it.
  Kyverno's synchronized generate rules watch their trigger, and a trigger
  that stops matching is treated like a deleted one.
- **The sidecar needs the rollout.** A pod's container list is immutable after
  admission, so no policy can take the gate out of a running pod. The
  Deployment patch above is enough to make the next pods come up ungated;
  `kubectl -n hello rollout restart deploy/hello-app` is what makes it now.

Visitors holding a renewal service worker retire it themselves once the gate's
endpoints stop answering; `/.anteroom/uninstall` does it immediately.

**Order matters in one place.** Deleting the ClusterPolicies while Services
still carry `proxied: enabled` leaves them targeting the port name `anteroom`
with no rule left to revert them, and the next ungated rollout blackholes.
Remove the Service label first, while the restore rule still exists. The chart
README's [table of what cleans itself up](../../charts/kyverno-policies/README.md#opting-out-and-what-cleans-itself-up)
covers the rest, including the asymmetry at uninstall: `helm uninstall` deletes
the generated ConfigMaps and NetworkPolicies in every namespace and leaves the
cloned Secrets behind.

## Finding what still needs a rollout

The `audit-anteroom-drift` policy exists for the one state that looks like
nothing: a pod carrying `inject: enabled` with no gate container, which happens
when it was admitted while the injection policy was not running — the chart not
yet installed, Kyverno's webhook down. From outside it is indistinguishable
from the app being down, and a Service already rewritten to `anteroom` cannot
reach it at all. It is Audit only, so it reports rather than refuses:

```sh
kubectl -n hello get policyreport -o wide
kubectl -n hello describe policyreport | grep -A 5 audit-anteroom-drift
```

A `fail` there names a pod to roll. Try it by uninstalling the policies chart,
rolling the workload, and looking again — the pods come back ungated and the
report says so.
