{{/*
Copyright Broadcom, Inc. All Rights Reserved.
SPDX-License-Identifier: APACHE-2.0
*/}}

{{/* vim: set filetype=mustache: */}}

{{/*
Returns an init-container that downloads src files from git repositories
*/}}
{{- define "pytorch.defaultInitContainers.gitCloneRepositories" -}}
- name: git-clone-repositories
  image: {{ include "pytorch.git.image" . }}
  imagePullPolicy: {{ .Values.git.pullPolicy | quote }}
  {{- if .Values.git.containerSecurityContext.enabled }}
  securityContext: {{- include "common.compatibility.renderSecurityContext" (dict "secContext" .Values.git.containerSecurityContext "context" .) | nindent 4 }}
  {{- end }}
  {{- if .Values.git.resources }}
  resources: {{- toYaml .Values.git.resources | nindent 4 }}
  {{- else if ne .Values.git.resourcesPreset "none" }}
  resources: {{- include "common.resources.preset" (dict "type" .Values.git.resourcesPreset) | nindent 4 }}
  {{- end }}
  command:
    - /bin/bash
  args:
    - -ec
    - |
      [[ -f "/opt/bitnami/scripts/git/entrypoint.sh" ]] && source "/opt/bitnami/scripts/git/entrypoint.sh"
      git clone {{ .Values.cloneFilesFromGit.repository }} --branch {{ .Values.cloneFilesFromGit.revision }} /app
  {{- if include "common.fips.enabled" . }}
  env:
    - name: OPENSSL_FIPS
      value: {{ include "common.fips.config" (dict "tech" "openssl" "fips" .Values.git.fips "global" .Values.global) | quote }}
  {{- end }}
  volumeMounts:
    - name: empty-dir
      mountPath: /app
      subPath: app-dir
    - name: empty-dir
      mountPath: /tmp
      subPath: tmp-dir
  {{- if .Values.cloneFilesFromGit.extraVolumeMounts }}
    {{- include "common.tplvalues.render" (dict "value" .Values.cloneFilesFromGit.extraVolumeMounts "context" .) | nindent 4 }}
  {{- end }}
{{- end -}}

{{/*
Returns an init-container that changes the owner and group of the persistent volume(s) mountpoint(s) to 'runAsUser:fsGroup' on each node
*/}}
{{- define "pytorch.defaultInitContainers.volumePermissions" -}}
- name: volume-permissions
  image: {{ include "pytorch.volumePermissions.image" . }}
  imagePullPolicy: {{ .Values.volumePermissions.image.pullPolicy | quote }}
  {{- if .Values.volumePermissions.containerSecurityContext.enabled }}
  securityContext: {{- include "common.compatibility.renderSecurityContext" (dict "secContext" .Values.volumePermissions.containerSecurityContext "context" .) | nindent 4 }}
  {{- end }}
  {{- if .Values.volumePermissions.resources }}
  resources: {{- toYaml .Values.volumePermissions.resources | nindent 4 }}
  {{- else if ne .Values.volumePermissions.resourcesPreset "none" }}
  resources: {{- include "common.resources.preset" (dict "type" .Values.volumePermissions.resourcesPreset) | nindent 4 }}
  {{- end }}
  {{- if include "common.fips.enabled" . }}
  env:
    - name: OPENSSL_FIPS
      value: {{ include "common.fips.config" (dict "tech" "openssl" "fips" .Values.volumePermissions.fips "global" .Values.global) | quote }}
  {{- end }}
  command:
    - /bin/bash
  args:
    - -ec
    - |
      mkdir -p {{ .Values.persistence.mountPath }}
      {{- if eq ( toString ( .Values.volumePermissions.containerSecurityContext.runAsUser )) "auto" }}
      find {{ .Values.persistence.mountPath }} -mindepth 1 -maxdepth 1 -not -name ".snapshot" -not -name "lost+found" |  xargs -r chown -R $(id -u):$(id -G | cut -d " " -f2)
      {{- else }}
      find {{ .Values.persistence.mountPath }} -mindepth 1 -maxdepth 1 -not -name ".snapshot" -not -name "lost+found" |  xargs -r chown -R {{ .Values.containerSecurityContext.runAsUser }}:{{ .Values.podSecurityContext.fsGroup }}
      {{- end }}
  volumeMounts:
    - name: data
      mountPath: {{ .Values.persistence.mountPath }}
{{- end -}}
