{{- define "immich-device-auth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "immich-device-auth.fullname" -}}
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

{{- define "immich-device-auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "immich-device-auth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "immich-device-auth.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "immich-device-auth.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "immich-device-auth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "immich-device-auth.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "immich-device-auth.publicUrl" -}}
{{- required "publicUrl is required: the URL phones open after scanning the QR code, e.g. https://device.photos.example.com" .Values.publicUrl | trimSuffix "/" -}}
{{- end -}}

{{- define "immich-device-auth.ingressHost" -}}
{{- default (urlParse (include "immich-device-auth.publicUrl" .)).host .Values.ingress.host -}}
{{- end -}}
