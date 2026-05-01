{{- define "discoveryCronJob.envs" -}}
{{- if or .discoveryCronJob.namespace_secrets .discoveryCronJob.env -}}
env:
{{- if .discoveryCronJob.namespace_secrets -}}
{{- range $secret, $envs := .discoveryCronJob.namespace_secrets }}
  {{- range $key, $val := $envs }}
  - name: {{ $key }}
    valueFrom:
      secretKeyRef:
        key: {{ trimSuffix "?" $val }}
        name: {{ $secret }}{{ if hasSuffix "?" $val }}
        optional: true{{ end }}  {{- end }}
{{- end }}
{{- end }}
{{- if .discoveryCronJob.env -}}
{{- range $key, $val := .discoveryCronJob.env }}
  - name: {{ $key }}
    value: {{ quote $val }}
{{- end }}
{{- end }}
{{- end -}}
{{- end -}}
