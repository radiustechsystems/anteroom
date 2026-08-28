#!/usr/bin/env bash
#
# Stand the whole example up on a local kind cluster, end to end:
#
#   1. create a kind cluster (skipped if it already exists)
#   2. install Kyverno via Helm
#   3. build the gate and hello-app from this checkout, load them into the cluster
#   4. mint the HMAC key Secret the generate policy clones
#   5. apply manifests/ — RBAC, then policies, then the demo workload
#   6. start port-forwards and print where everything is reachable
#
# The script is idempotent: run it again and every step that is already done
# is skipped, ending back at the port-forwards. Ctrl-C stops the forwards and
# leaves the cluster running; delete it with:
#
#   kind delete cluster --name anteroom-demo
#
# Requires: docker, kind, kubectl, helm, openssl.

set -euo pipefail

CLUSTER=anteroom-demo
EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Local ports for the forwards. Override from the environment if taken.
GATE_PORT="${GATE_PORT:-8080}"       # -> svc/hello-app :80, through the gate
METRICS_PORT="${METRICS_PORT:-8090}" # -> the sidecar's admin listener
APP_PORT="${APP_PORT:-3000}"         # -> hello-app directly, bypassing the gate

# Where the Kyverno chart comes from. The default adds the hosted repo; point
# this at a chart tarball instead (KYVERNO_CHART=./kyverno-3.3.7.tgz) when the
# repo is unreachable — an air-gapped or egress-filtered network.
KYVERNO_CHART="${KYVERNO_CHART:-kyverno/kyverno}"

# The gate image, built from this checkout below. The name must be exactly
# what the injection policy references — the kubelet matches loaded images by
# name, and the policy's imagePullPolicy: IfNotPresent is what lets the
# loaded image win over a registry pull.
GATE_IMAGE=ghcr.io/radiustechsystems/anteroom:latest

say()  { printf '\n==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }

need docker; need kind; need kubectl; need helm; need openssl

say "kind cluster"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "cluster $CLUSTER already exists — reusing it"
else
  kind create cluster --name "$CLUSTER"
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

say "Kyverno"
if [ "$KYVERNO_CHART" = "kyverno/kyverno" ]; then
  helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
fi
# upgrade --install rather than a status check: idempotent on re-runs, and it
# recovers the half-finished release an interrupted first run leaves behind,
# which a plain `helm install` refuses to replace and a "release exists" skip
# would silently accept. --wait matters: policies applied before the
# admission webhooks are up would be accepted but not enforced, and the demo
# pods would be admitted ungated.
helm upgrade --install kyverno "$KYVERNO_CHART" -n kyverno --create-namespace --wait

say "images"
# The gate, built from this checkout rather than pulled: the demo then runs
# the code you have, works without registry access, and no release can change
# it under you. It is loaded under the name the policy references (see
# GATE_IMAGE above). SKIP_BUILD=1 skips the builds and loads whatever images
# already carry these names — for machines where `docker build` has no
# network and the images were built or fetched some other way.
if [ "${SKIP_BUILD:-}" != "1" ]; then
  docker build -q -t "$GATE_IMAGE" "$EXAMPLE_DIR/../.."
  docker build -q -t hello-app:local "$EXAMPLE_DIR/../hello-app"
fi
kind load docker-image "$GATE_IMAGE" hello-app:local --name "$CLUSTER"

say "signing key"
# Minted once and kept: rotating it on every run would wall every visitor
# holding a pass. Keep the key out of manifests — a committed key is a
# published key.
kubectl get namespace anteroom-system >/dev/null 2>&1 \
  || kubectl create namespace anteroom-system
if kubectl -n anteroom-system get secret anteroom >/dev/null 2>&1; then
  echo "secret anteroom-system/anteroom already exists — keeping it"
else
  kubectl -n anteroom-system create secret generic anteroom \
    --from-literal=hmac-key="$(openssl rand -base64 32)"
fi

say "policies"
# rbac.yaml first, and not just first in the directory: Kyverno's
# policy-validation webhook refuses the generate policy until the controllers
# hold the permissions it needs, and the grant lands via ClusterRole
# aggregation, which is asynchronous — so wait until the aggregated
# permission is actually visible before applying the policies.
kubectl apply -f "$EXAMPLE_DIR/manifests/policies/rbac.yaml"
for _ in $(seq 1 30); do
  kubectl auth can-i list secrets \
    --as=system:serviceaccount:kyverno:kyverno-admission-controller \
    >/dev/null 2>&1 && break
  sleep 2
done
kubectl apply -f "$EXAMPLE_DIR/manifests/policies/"
# Ready means the webhook rules are registered; without this wait the demo
# namespace could race past an unconfigured webhook and come up ungated.
kubectl wait --for=condition=Ready clusterpolicy --all --timeout=120s

say "demo workload"
kubectl apply -f "$EXAMPLE_DIR/manifests/demo/"
# The pods wait on the generated ConfigMap and cloned Secret before they can
# start, so a slow generate shows up here as ContainerCreating, then resolves.
kubectl -n hello rollout status deploy/hello-app --timeout=180s

say "checking the gate is in the path"
tp="$(kubectl -n hello get svc hello-app -o jsonpath='{.spec.ports[0].targetPort}')"
if [ "$tp" != "anteroom" ]; then
  echo "Service targetPort is '$tp', expected 'anteroom' — the Service policy did not apply" >&2
  exit 1
fi
echo "Service targetPort: $tp"
kubectl -n hello get pods

say "port-forwards"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Through the Service, so this is the path a visitor takes: rewritten
# targetPort, gate, then the app.
kubectl -n hello port-forward svc/hello-app "$GATE_PORT:80" >/dev/null &
pids+=($!)
# Straight to one pod: the admin listener on the sidecar's loopback, and the
# app's own port with no gate in front — useful for comparing the two.
kubectl -n hello port-forward deploy/hello-app \
  "$METRICS_PORT:8090" "$APP_PORT:3000" >/dev/null &
pids+=($!)
sleep 2

cat <<EOF

Port-forwards are up (Ctrl-C stops them; the cluster stays):

  anteroom (the gated site)   http://localhost:$GATE_PORT
      svc/hello-app -> targetPort "anteroom" -> gate -> 127.0.0.1:3000.
      Open it in a browser: wait page, ~1s puzzle, then hello-app.
      localhost is a secure context, so WebCrypto and renewal work.

  anteroom metrics            http://localhost:$METRICS_PORT/metrics
      The sidecar's admin listener (also /stats and /healthz). Bound to the
      pod's loopback — reachable through port-forward, not from the cluster.

  upstream service (ungated)  http://localhost:$APP_PORT
      hello-app directly, bypassing the gate — what the cluster-internal
      side door looks like, and why the README suggests a NetworkPolicy.

Try:
  curl -si http://localhost:$GATE_PORT/ | head -1      # 401: the gate answers
  curl -si http://localhost:$APP_PORT/  | head -1      # 200: the app, ungated
  curl -s  http://localhost:$METRICS_PORT/metrics | head

Tear down with: kind delete cluster --name $CLUSTER
EOF

wait
