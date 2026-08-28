# Anteroom by admission policy: Kyverno sidecar injection

The Compose sidecar in [`../anteroomized/`](../anteroomized/) is one gate
wired to one app by hand. This example is the same topology run as cluster
policy: label a workload and [Kyverno](https://kyverno.io) injects the gate,
rewires the Service through it, and provisions the config and signing key the
sidecar mounts — the application manifests never mention Anteroom at all.

Three policies, one job each:

| Policy | Acts on | What it does |
| --- | --- | --- |
| [`policies/inject-anteroom-sidecar.yaml`](policies/inject-anteroom-sidecar.yaml) | Pods | injects the gate as a sidecar proxy container, forwarding to `127.0.0.1:<upstream-port>` |
| [`policies/route-service-through-anteroom.yaml`](policies/route-service-through-anteroom.yaml) | Services | rewrites every `targetPort` to the named port `anteroom`, putting the gate in the traffic path |
| [`policies/generate-anteroom-config.yaml`](policies/generate-anteroom-config.yaml) | Namespaces | generates the `anteroom-config` ConfigMap and clones the `anteroom` HMAC Secret into the namespace |

Plus [`policies/rbac.yaml`](policies/rbac.yaml), the grant Kyverno's
background controller needs to create what the generate policy declares, and
[`demo/`](demo/), a two-replica `hello-app` behind the gate.

## The opt-in surface

Everything is explicit, and each resource asks for its own rewrite:

| Where | Metadata | Meaning |
| --- | --- | --- |
| Namespace | label `anteroom.radiustech.xyz/inject: enabled` | generate the ConfigMap, clone the key |
| Pod template | label `anteroom.radiustech.xyz/inject: enabled` | inject the sidecar |
| Pod template | annotation `anteroom.radiustech.xyz/upstream-port: "3000"` | where the app listens; **required** with the label — a missing port is an admission error, not a guessed default |
| Service | label `anteroom.radiustech.xyz/proxied: enabled` | rewrite `targetPort` to the gate |

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

Requirements: a cluster, Kyverno 1.11+
installed ([their quick start](https://kyverno.io/docs/installation/)), and a
place to put the source Secret. With [kind](https://kind.sigs.k8s.io):

```sh
kind create cluster
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace

# Build the demo app and hand it to the cluster.
docker build -t hello-app:local ../hello-app
kind load docker-image hello-app:local
```

Mint the deployment key once, into the namespace the generate policy clones
from. Keep it out of manifests and repositories — a committed key is a
published key:

```sh
kubectl create namespace anteroom-system
kubectl -n anteroom-system create secret generic anteroom \
  --from-literal=hmac-key="$(openssl rand -base64 32)"
```

Apply the policies, then the demo:

```sh
kubectl apply -f policies/
kubectl apply -f demo/
```

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
# HTTP/1.1 401 Unauthorized
```

Then see it as a visitor. Port-forwarding lands on `localhost`, which is a
secure context, so the puzzle runs and the wait page resolves into the app in
about a second:

```sh
kubectl -n hello port-forward svc/hello-app 8080:80
# browse http://localhost:8080
```

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

**Probes keep working, and that is not a bypass hole.** The kubelet dials the
app's `containerPort` from inside the node, never through the Service, so app
probes need no `[bypass]` entry and the gate never sees them.

## The side door, and the two traps

**Any pod can still dial the app directly.** Rewriting the Service moves
*Service* traffic behind the gate, but the pod IP answers on `:3000` to
anyone in the cluster — the Kubernetes equivalent of the Compose app that
still publishes its own port. Whether that matters depends on who shares your
cluster; the fence, if you need one, is a NetworkPolicy admitting only the
gate's port:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: only-through-anteroom
  namespace: hello
spec:
  podSelector:
    matchLabels:
      anteroom.radiustech.xyz/inject: enabled
  ingress:
    - ports:
        - port: 8080   # numeric: NetworkPolicy resolves numbers, and the
                       # injected containerPort is always 8080
```

It is deliberately not one of the generated resources, because its failure
mode is CNI-dependent: kubelet probe traffic is exempted by some network
plugins (Cilium, Calico in default configurations) and blocked by others, and
a blocked probe kills healthy pods. Verify probes survive on *your* CNI before
adopting it, and note it needs a CNI that enforces NetworkPolicy at all.

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

Remove the three labels and roll the workloads; pods come back without the
sidecar and the Service reverts on its next apply. Visitors holding a renewal
service worker retire it themselves once the gate's endpoints stop answering;
`/.anteroom/uninstall` does it immediately. Deleting the ClusterPolicies with
the labels still in place also works — Kyverno mutates only at admission, so
nothing changes until the next rollout, which then comes up ungated **while
the Service still targets port `anteroom`**; remove the Service label first.
