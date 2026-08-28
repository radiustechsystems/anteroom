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
