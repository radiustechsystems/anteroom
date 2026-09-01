{{/*
Standard labels for everything the chart creates. The policies are
cluster-scoped singletons with fixed names, so install this chart once per
cluster; the instance label records which release owns them.
*/}}
{{- define "kyverno-policies.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: anteroom
{{- end }}

{{/*
The gate's listening port, as a number, in one place.

Deliberately not a value. Between the policies the port is referred to by the
NAME "anteroom" — that is what decouples the Service rewrite from the
injection — and the number is an implementation detail nobody needs to
configure. But NetworkPolicy is the exception: `ports[].port` is resolved by
the CNI against the pod, and a named port there is honored inconsistently
across plugins, so the fence has to say 8080 in digits.

Two templates therefore need the same number, which is exactly the situation
a constant exists for: change it here and the injected containerPort and the
port the fence admits cannot drift apart.
*/}}
{{- define "kyverno-policies.gatePort" -}}8080{{- end }}

{{/*
Precondition: this Service actually has ports.

`spec.ports` is optional in the API — an ExternalName Service has none, and a
selectorless one need not — and every rule here either iterates it or
serializes it. Kyverno raises `Unknown key "ports"` on the missing field
rather than yielding an empty list, and a mutate rule that errors is an
admission failure under Kyverno's default failurePolicy: Fail. So a Service
that cannot be proxied would be refused outright instead of simply left
alone, which is a bad trade for a label someone applied by mistake.

`to_string()` is the null-safe probe: it answers the literal string "null"
for an absent key instead of erroring, which no real port list can produce.
*/}}
{{- define "kyverno-policies.hasPorts" -}}
- key: {{ `"{{ to_string(request.object.spec.ports) }}"` }}
  operator: NotEquals
  value: "null"
{{- end }}
