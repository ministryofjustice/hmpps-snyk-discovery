{{- define "snykScanCronJob.envs" -}}
{{- if or .snykScanCronJob.namespace_secrets .snykScanCronJob.env -}}
env:
{{- if .snykScanCronJob.namespace_secrets -}}
{{- range $secret, $envs := .snykScanCronJob.namespace_secrets }}
  {{- range $key, $val := $envs }}
  {{- if ne $key "GHCR_AUTH_CONFIG" }}
  - name: {{ $key }}
    valueFrom:
      secretKeyRef:
        key: {{ trimSuffix "?" $val }}
        name: {{ $secret }}{{ if hasSuffix "?" $val }}
        optional: true{{ end }}
  {{- end }}
  {{- end }}
{{- end }}
{{- end }}
{{- if .snykScanCronJob.env -}}
{{- range $key, $val := .snykScanCronJob.env }}
  - name: {{ $key }}
    value: {{ quote $val }}
{{- end }}
{{- end }}
{{- end -}}
{{- end -}}
