# Bitnami Secure Charts Mirror

Unofficial mirror of the free Bitnami Secure OCI charts and images.

This repository tracks selected charts from `registry-1.docker.io/bitnamichartssecure`, mirrors the `bitnamisecure/*:latest` images referenced by each chart into Docker Hub namespace `inglp`, pins them by digest, and publishes patched Helm OCI charts.

## Enabled Charts

Configured in `charts.yaml`:

- `common`
- `redis`
- `valkey`
- `mariadb`
- `postgresql`

## Available Upstream Secure Charts

As of 2026-05-07, Docker Hub exposes these Helm chart repositories in `bitnamichartssecure`:

- `aspnet-core`
- `common`
- `haproxy`
- `mariadb`
- `memcached`
- `mongodb`
- `nginx`
- `postgresql`
- `pytorch`
- `redis`
- `tomcat`
- `valkey`
- `wordpress`

Non-chart OCI repositories in the same namespace include `charts-index` and `vac-health-check`.

## Available Upstream Secure Images

The free `bitnamisecure` namespace is larger than the secure chart catalog. Use:

```sh
uv run bitnami-secure-charts available-images
```

to list the current public image repositories.

## How It Works

The sync job:

1. reads `charts.yaml`;
2. discovers the latest Helm chart tag for each selected chart;
3. pulls the upstream OCI chart;
4. reads the chart `annotations.images` metadata;
5. inspects each referenced `bitnamisecure/*:latest` image;
6. copies each image into Docker Hub as `inglp/bitnami-secure-<image>:<app-version>-<os-flavour>-r<revision>`;
7. patches chart default image values to the mirrored repository, human-readable tag, and immutable digest;
8. patches chart dependencies from `bitnamichartssecure` to `inglp`;
9. packages and pushes the chart to `oci://registry-1.docker.io/inglp`;
10. commits generated `charts/` and `locks/` updates.

## Required GitHub Secrets

The workflow expects:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

GitHub repository secrets are usually scoped per repository. If these secrets only exist on an older repo, recreate them here with the same names.

Create them in GitHub at:

`Settings` -> `Secrets and variables` -> `Actions` -> `New repository secret`

Use:

- `DOCKERHUB_USERNAME`: your Docker Hub username or namespace, expected here to be `inglp`.
- `DOCKERHUB_TOKEN`: a Docker Hub personal access token with read/write access.

Create the Docker Hub token from:

`Docker Hub` -> account menu -> `Account settings` -> `Personal access tokens` -> `Generate new token`

The token value is shown only once. Store that value as `DOCKERHUB_TOKEN`.

## Manual Commands

List available secure charts:

```sh
uv run bitnami-secure-charts available-charts
```

Run a local dry sync without pushing images or charts:

```sh
uv run bitnami-secure-charts sync
```

Sync and publish one chart:

```sh
uv run bitnami-secure-charts sync --push --chart redis
```

## Scope

This mirror does not build images from source and does not provide Broadcom/Bitnami commercial support, CVE guarantees, SLAs, or long-term retention promises beyond what is mirrored into this namespace.
