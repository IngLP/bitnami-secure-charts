# Bitnami Secure Charts Mirror

Unofficial mirror of the free Bitnami Secure charts and images.

This repository tracks selected charts from `registry-1.docker.io/bitnamichartssecure`, mirrors the `bitnamisecure/*:latest` images referenced by each chart into Docker Hub namespace `inglp`, pins them by digest, and publishes patched charts through a classic Helm repository on GitHub Pages.

## Enabled Charts

Configured in `charts.yaml`:

- `common`
- `haproxy`
- `mariadb`
- `memcached`
- `mongodb`
- `nginx`
- `postgresql`
- `redis`
- `valkey`
- `wordpress`

`postgres` is tracked as `postgresql`, which is the upstream Bitnami chart name.

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
8. patches chart dependencies from `bitnamichartssecure` to `https://inglp.github.io/bitnami-secure-charts`;
9. packages the chart with an immutable mirror version such as `25.5.2-inglp.r0`;
10. commits generated `charts/` and `locks/` updates.

If Bitnami changes an image digest without changing the upstream chart version, this mirror increments the chart revision instead of overwriting the previous chart content:

- first mirror of upstream `25.5.2` -> `25.5.2-inglp.r0`
- same upstream chart version with changed image digest -> `25.5.2-inglp.r1`
- next upstream chart version `25.5.3` -> `25.5.3-inglp.r0`

The lock file keeps `upstream_version`, the published mirror `version`, mirrored dependency versions, and a content fingerprint built from the upstream chart digest, mirrored dependency versions, and referenced image digests.

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

Stage one chart locally, including mirrored images and publishable chart packages under `dist/publish`:

```sh
uv run bitnami-secure-charts sync --push --chart redis
```

The GitHub Actions workflow performs the actual GitHub Pages publish and then runs `confirm-published` before committing generated locks. For manual publishing, only commit generated `charts/` and `locks/` after publishing `dist/publish/*.tgz` to the Helm repository and running:

```sh
uv run bitnami-secure-charts confirm-published
```

Pull a mirrored chart:

```sh
helm repo add inglp-bitnami-secure https://inglp.github.io/bitnami-secure-charts
helm repo update
helm pull inglp-bitnami-secure/redis --version 25.5.2-inglp.r0
```

## Scope

This mirror does not build images from source and does not provide Broadcom/Bitnami commercial support, CVE guarantees, SLAs, or long-term retention promises beyond what is mirrored into this namespace.
