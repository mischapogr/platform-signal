{{- define "signal.name" -}}
{{- printf "%s-signal" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "signal.selector" -}}
app.kubernetes.io/name: signal
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "signal.labels" -}}
{{ include "signal.selector" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}
