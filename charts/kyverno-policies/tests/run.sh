#!/usr/bin/env bash
#
# What the policies actually do, checked without a cluster.
#
# Every policy in this chart is a claim about what the API server will store
# after admission, and until now those claims were only checked by reading
# them. `kyverno apply` evaluates a rendered policy against a resource file
# offline and prints what it would have produced, which turns each claim into
# a diff against a committed expectation.
#
# Worth being clear about the boundary: this proves the POLICIES are right —
# preconditions fire where intended, the mutations land where intended, the
# generated objects have the fields intended. It cannot prove anything about
# what a CNI does with a NetworkPolicy, or that a kubelet probe survives one.
# That is examples/kyverno/ and a real cluster.
#
# Each case renders ONE policy template and applies it alone. The isolation is
# not tidiness: at admission Kyverno runs all mutations before any validation,
# so the drift audit rule below would always see an already-injected pod and
# always pass. Applying it by itself is what reproduces the case it exists
# for — a background scan meeting a pod that was admitted ungated.
#
# Requires: helm, kyverno (https://kyverno.io/docs/kyverno-cli/), python3.
#
#   ./run.sh              check every case against tests/expected/
#   ./run.sh --update     rewrite tests/expected/ from current behavior
#
# --update is for when a policy change is meant to change the output: run it,
# then read the resulting diff as the review of your own change.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="$(dirname "$HERE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need helm; need kyverno; need python3

# Pinned so the chart's own kubeVersion floor is what is being honored, not
# whatever version the local helm happens to assume (older helm defaults below
# the chart's >=1.25 floor and refuses to render at all).
KUBE_VERSION=1.29.0

fail=0
checked=0

# Strip everything that is true of the run rather than of the policy, so a
# chart version bump or a Kyverno CLI upgrade does not rewrite every
# expectation: Kyverno's generate bookkeeping labels (which carry the trigger's
# identity) and the chart's own version label.
normalize() {
  python3 - "$1" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
# kyverno apply emits the resource once per policy considered; the last
# document is the one carrying that policy's patches.
doc = docs[-1]
labels = doc.get("metadata", {}).get("labels")
if labels:
    for k in list(labels):
        if k.startswith("generate.kyverno.io/") or k == "helm.sh/chart":
            del labels[k]
    if not labels:
        del doc["metadata"]["labels"]
print(yaml.safe_dump(doc, default_flow_style=False, sort_keys=True), end="")
PY
}

render() { # render(template, extra helm args...) -> path to rendered policy
  local tmpl="$1"; shift
  local out="$WORK/policy-$(basename "$tmpl" .yaml)-$RANDOM.yaml"
  helm template anteroom-policies "$CHART" \
    --kube-version "$KUBE_VERSION" \
    --show-only "templates/$tmpl" "$@" > "$out"
  echo "$out"
}

# compare(name, produced-file, golden-basename)
compare() {
  local name="$1" produced="$2" golden="$HERE/expected/$3"
  checked=$((checked + 1))
  local got; got="$(normalize "$produced")"
  if [ "$UPDATE" = 1 ]; then
    mkdir -p "$HERE/expected"
    printf '%s\n' "$got" > "$golden"
    echo "  updated  $name"
    return
  fi
  if [ ! -f "$golden" ]; then
    echo "  MISSING  $name — no expectation at ${golden#"$HERE"/}; run --update" >&2
    fail=1
    return
  fi
  if diff -u "$golden" <(printf '%s\n' "$got") > "$WORK/diff" 2>&1; then
    echo "  ok       $name"
  else
    echo "  FAIL     $name" >&2
    sed 's/^/           /' "$WORK/diff" >&2
    fail=1
  fi
}

# mutates(name, template, resource, golden, extra helm args...)
mutates() {
  local name="$1" tmpl="$2" res="$3" golden="$4"; shift 4
  local policy out; policy="$(render "$tmpl" "$@")"
  out="$WORK/out-$RANDOM"; mkdir -p "$out"
  kyverno apply "$policy" --resource "$HERE/resources/$res" -o "$out" >/dev/null 2>&1 || true
  local produced; produced="$(find "$out" -name '*-mutated.yaml' | head -1)"
  if [ -z "$produced" ]; then
    echo "  FAIL     $name — no mutation produced (rule skipped or errored)" >&2
    kyverno apply "$policy" --resource "$HERE/resources/$res" 2>&1 | tail -5 | sed 's/^/           /' >&2
    fail=1; checked=$((checked + 1)); return
  fi
  compare "$name" "$produced" "$golden"
}

# generates(name, template, resource, golden, extra helm args...)
generates() {
  local name="$1" tmpl="$2" res="$3" golden="$4"; shift 4
  local policy out; policy="$(render "$tmpl" "$@")"
  out="$WORK/out-$RANDOM"; mkdir -p "$out"
  kyverno apply "$policy" --resource "$HERE/resources/$res" -o "$out" >/dev/null 2>&1 || true
  local produced; produced="$(find "$out" -name '*-generated.yaml' | head -1)"
  if [ -z "$produced" ]; then
    echo "  FAIL     $name — nothing generated" >&2
    fail=1; checked=$((checked + 1)); return
  fi
  compare "$name" "$produced" "$golden"
}

# counts(name, template, resource, expected-summary-fragment, extra helm args...)
#
# For the cases whose whole content is "the rule did not fire" or "the rule
# failed the resource", where a golden file would just be the input again.
counts() {
  local name="$1" tmpl="$2" res="$3" want="$4"; shift 4
  local policy summary; policy="$(render "$tmpl" "$@")"
  checked=$((checked + 1))
  # `kyverno apply` exits non-zero whenever a resource failed a rule, which
  # for the audit cases below is the expected result — so its status is not the
  # assertion here, the summary line is. Swallow it, or pipefail turns a
  # correctly-reported violation into an aborted test run.
  summary="$( { kyverno apply "$policy" --resource "$HERE/resources/$res" 2>&1 || true; } \
    | grep -oE 'pass: [0-9]+, fail: [0-9]+, warn: [0-9]+, error: [0-9]+, skip: [0-9]+' | tail -1)"
  if [ "$summary" = "$want" ]; then
    echo "  ok       $name"
  else
    echo "  FAIL     $name" >&2
    echo "           want: $want" >&2
    echo "           got:  ${summary:-<no summary>}" >&2
    fail=1
  fi
}

SVC=clusterpolicy-route-service.yaml
NP=clusterpolicy-generate-config.yaml
AUDIT=clusterpolicy-audit-drift.yaml

echo "Service rewrite and its reverse:"

# The ordinary case: the original ports are recorded, then every targetPort is
# rewritten to the gate's named port.
mutates "labeled Service is rewritten, original recorded" \
  "$SVC" service-labeled.yaml service-labeled.yaml

# The case that decides how the record is stored. This port has no explicit
# targetPort — it defaults to `port` at resolution time — so the record has to
# be able to say "absent", which a port-to-value map cannot. Storing the array
# verbatim can, and this is the test that holds it to that.
mutates "implicit targetPort survives the round trip" \
  "$SVC" service-labeled-implicit-targetport.yaml service-labeled-implicit-targetport.yaml

# The cleanup half: the label is gone, the record is present, so the ports go
# back and the record is dropped. Without this the Service would keep
# targeting the port name "anteroom" and blackhole once its pods roll ungated.
mutates "removing the label restores the original ports" \
  "$SVC" service-unlabeled-with-record.yaml service-restored.yaml

# Every other Service in the cluster. The restore rule matches them (it
# selects the absence of a label) and must do nothing at all.
counts "unrelated Service is left alone" \
  "$SVC" service-unlabeled-plain.yaml \
  "pass: 0, fail: 0, warn: 0, error: 0, skip: 1"

# spec.ports is optional in the API, and a mutate rule that errors is an
# admission failure under Kyverno's default failurePolicy — so a Service that
# simply cannot be proxied has to be skipped, not refused.
counts "port-less Service is skipped, not refused" \
  "$SVC" service-externalname-labeled.yaml \
  "pass: 0, fail: 0, warn: 0, error: 0, skip: 2"

# The record/restore pair is switchable, and with it off the rewrite must
# still be exactly what it always was.
mutates "with restoreService off, only the rewrite happens" \
  "$SVC" service-labeled.yaml service-labeled-no-record.yaml \
  --set policies.restoreService=false

echo
echo "NetworkPolicy fence:"

generates "opted-in namespace gets the fence" \
  "$NP" namespace-opted-in.yaml networkpolicy.yaml \
  --set admin.networkPolicy.enabled=true \
  --set policies.generateConfig=false --set hmacSecret.clone=false

# extraIngress is the probe escape hatch and the metrics escape hatch; if it
# did not append cleanly, the advice in the README would be wrong.
generates "extraIngress rules are appended" \
  "$NP" namespace-opted-in.yaml networkpolicy-extra-ingress.yaml \
  --set admin.networkPolicy.enabled=true \
  --set policies.generateConfig=false --set hmacSecret.clone=false \
  --set 'admin.networkPolicy.extraIngress[0].from[0].ipBlock.cidr=10.0.0.0/16'

counts "namespace without the label gets nothing" \
  "$NP" namespace-plain.yaml \
  "pass: 0, fail: 0, warn: 0, error: 0, skip: 0" \
  --set admin.networkPolicy.enabled=true

echo
echo "Drift audit:"

# A pod that opted in and never got a gate. Applied alone on purpose — with
# the injection policy loaded, admission would mutate it first and this rule
# would have nothing to report.
counts "labeled pod with no gate is reported" \
  "$AUDIT" pod-ungated.yaml \
  "pass: 0, fail: 1, warn: 0, error: 0, skip: 0"

counts "labeled pod carrying the gate passes" \
  "$AUDIT" pod-gated.yaml \
  "pass: 1, fail: 0, warn: 0, error: 0, skip: 0"

counts "unlabeled pod is not audited" \
  "$AUDIT" pod-unlabeled.yaml \
  "pass: 0, fail: 0, warn: 0, error: 0, skip: 0"

echo
if [ "$fail" = 0 ]; then
  echo "$checked case(s) ok"
else
  echo "FAILED — see above" >&2
  exit 1
fi
