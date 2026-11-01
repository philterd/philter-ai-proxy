{{/*
Expand the name of the chart.
*/}}
{{- define "philter-ai-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Respects fullnameOverride.
*/}}
{{- define "philter-ai-proxy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label.
*/}}
{{- define "philter-ai-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard labels.
*/}}
{{- define "philter-ai-proxy.labels" -}}
helm.sh/chart: {{ include "philter-ai-proxy.chart" . }}
{{ include "philter-ai-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels (match labels for Deployment/Service selectors).
*/}}
{{- define "philter-ai-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "philter-ai-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "philter-ai-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "philter-ai-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference. Uses image.tag if set, otherwise the chart's appVersion.
*/}}
{{- define "philter-ai-proxy.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Name of the Secret holding the TLS certificate (tls.crt, tls.key) when tls.mode is existingSecret or certManager.
*/}}
{{- define "philter-ai-proxy.tlsSecretName" -}}
{{- if eq .Values.tls.mode "existingSecret" -}}
{{- required "tls.existingSecret is required when tls.mode=existingSecret" .Values.tls.existingSecret -}}
{{- else -}}
{{- default (printf "%s-tls" (include "philter-ai-proxy.fullname" .)) .Values.tls.certManager.secretName -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding encryption-key and bootstrap-api-key.
*/}}
{{- define "philter-ai-proxy.secretName" -}}
{{- default (printf "%s-secrets" (include "philter-ai-proxy.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{/*
The probe and test scheme: HTTPS unless tls.mode is none.
*/}}
{{- define "philter-ai-proxy.scheme" -}}
{{- if eq .Values.tls.mode "none" -}}HTTP{{- else -}}HTTPS{{- end -}}
{{- end -}}
