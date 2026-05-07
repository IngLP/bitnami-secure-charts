from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


SEMVER_TAG = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class SyncError(RuntimeError):
    """Raised when an external chart or image contract is not as expected."""


@dataclass(frozen=True)
class MirrorConfig:
    dockerhub_namespace: str
    upstream_chart_registry: str
    upstream_chart_namespace: str
    upstream_image_registry: str
    upstream_image_namespace: str
    target_image_prefix: str
    chart_names: tuple[str, ...]


@dataclass(frozen=True)
class ChartImage:
    name: str
    version: str
    image: str


@dataclass(frozen=True)
class MirroredImage:
    name: str
    source_image: str
    source_digest: str
    app_version: str
    os_flavour: str
    image_revision: str
    target_registry: str
    target_repository: str
    target_tag: str
    target_digest: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bitnami-secure-charts")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("available-charts", "available-images"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--config", default="charts.yaml")

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--config", default="charts.yaml")
    sync_parser.add_argument("--chart", action="append", dest="charts")
    sync_parser.add_argument("--push", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "available-charts":
        config = load_config(Path(args.config))
        for name in list_available_repositories(config.upstream_chart_namespace, content_type="helm"):
            print(name)
        return 0

    if args.command == "available-images":
        config = load_config(Path(args.config))
        for name in list_available_repositories(config.upstream_image_namespace):
            print(name)
        return 0

    if args.command == "sync":
        config = load_config(Path(args.config))
        sync(config=config, requested_charts=tuple(args.charts or ()), push=args.push)
        return 0

    raise AssertionError(f"Unhandled command: {args.command}")


def load_config(path: Path) -> MirrorConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    chart_names = tuple(chart["name"] for chart in raw["charts"])
    if len(chart_names) != len(set(chart_names)):
        raise SyncError("charts.yaml contains duplicate chart names")
    return MirrorConfig(
        dockerhub_namespace=raw["dockerhub_namespace"],
        upstream_chart_registry=raw["upstream_chart_registry"],
        upstream_chart_namespace=raw["upstream_chart_namespace"],
        upstream_image_registry=raw["upstream_image_registry"],
        upstream_image_namespace=raw["upstream_image_namespace"],
        target_image_prefix=raw["target_image_prefix"],
        chart_names=chart_names,
    )


def sync(config: MirrorConfig, requested_charts: tuple[str, ...], push: bool) -> None:
    selected = requested_charts or config.chart_names
    unknown = sorted(set(selected) - set(config.chart_names))
    if unknown:
        raise SyncError(f"Requested chart not present in charts.yaml: {', '.join(unknown)}")
    if requested_charts and "common" in config.chart_names and "common" not in selected:
        selected = ("common", *selected)

    root = Path.cwd()
    charts_dir = root / "charts"
    locks_dir = root / "locks"
    package_dir = root / "dist"
    charts_dir.mkdir(exist_ok=True)
    locks_dir.mkdir(exist_ok=True)
    package_dir.mkdir(exist_ok=True)

    for chart_name in selected:
        version = latest_chart_version(config, chart_name)
        sync_chart(config, chart_name, version, charts_dir, locks_dir, package_dir, push)


def sync_chart(
    config: MirrorConfig,
    chart_name: str,
    version: str,
    charts_dir: Path,
    locks_dir: Path,
    package_dir: Path,
    push: bool,
) -> None:
    chart_ref = f"oci://{config.upstream_chart_registry}/{config.upstream_chart_namespace}/{chart_name}"
    source_digest = dockerhub_tag_digest(config.upstream_chart_namespace, chart_name, version)
    chart_dir = charts_dir / chart_name
    if chart_dir.exists():
        shutil.rmtree(chart_dir)

    run(["helm", "pull", chart_ref, "--version", version, "--untar", "--untardir", str(charts_dir)])

    chart_yaml_path = chart_dir / "Chart.yaml"
    values_yaml_path = chart_dir / "values.yaml"
    chart_yaml = read_yaml(chart_yaml_path)
    values_yaml = read_yaml(values_yaml_path) if values_yaml_path.exists() else {}

    chart_images = parse_chart_images(chart_yaml.get("annotations", {}).get("images", "[]"))
    mirrors = [
        inspect_and_optionally_copy_image(config, chart_image, push)
        for chart_image in chart_images
    ]

    patch_chart_yaml(config, chart_yaml, chart_name, version, source_digest)
    patch_values_yaml(values_yaml, mirrors)
    write_yaml(chart_yaml_path, chart_yaml)
    if values_yaml_path.exists():
        write_yaml(values_yaml_path, values_yaml)

    if push:
        build_dependencies(chart_dir)
        package_path = package_chart(chart_dir, package_dir)
        run(["helm", "push", str(package_path), f"oci://{config.upstream_chart_registry}/{config.dockerhub_namespace}"])

    write_lock(locks_dir / f"{chart_name}.json", chart_name, version, source_digest, mirrors)


def latest_chart_version(config: MirrorConfig, chart_name: str) -> str:
    tags = dockerhub_tags(config.upstream_chart_namespace, chart_name)
    for tag in tags:
        if tag["content_type"] == "helm" and SEMVER_TAG.match(tag["name"]):
            return tag["name"]
    raise SyncError(f"No Helm semver tag found for {config.upstream_chart_namespace}/{chart_name}")


def parse_chart_images(raw_annotation: str) -> list[ChartImage]:
    parsed = yaml.safe_load(raw_annotation) or []
    return [
        ChartImage(name=item["name"], version=str(item["version"]), image=item["image"])
        for item in parsed
    ]


def inspect_and_optionally_copy_image(
    config: MirrorConfig,
    chart_image: ChartImage,
    push: bool,
) -> MirroredImage:
    source_image = normalize_source_image(config, chart_image.image)
    source_digest = skopeo_digest(source_image)
    source_repository = strip_tag(source_image)
    image_config = skopeo_config(f"{source_repository}@{source_digest}")
    env = parse_env(image_config["config"]["Env"])
    app_version = require_env(env, "APP_VERSION", source_image)
    os_flavour = require_env(env, "OS_FLAVOUR", source_image)
    image_revision = require_env(env, "IMAGE_REVISION", source_image)
    target_tag = build_target_tag(app_version, os_flavour, image_revision)
    image_name = source_image.rsplit("/", maxsplit=1)[1].split(":", maxsplit=1)[0]
    target_repository = f"{config.dockerhub_namespace}/{config.target_image_prefix}{image_name}"
    target_image = f"{config.upstream_chart_registry}/{target_repository}:{target_tag}"

    if push:
        run(["skopeo", "copy", "--all", f"docker://{source_repository}@{source_digest}", f"docker://{target_image}"])

    return MirroredImage(
        name=image_name,
        source_image=source_image,
        source_digest=source_digest,
        app_version=app_version,
        os_flavour=os_flavour,
        image_revision=image_revision,
        target_registry="docker.io",
        target_repository=target_repository,
        target_tag=target_tag,
        target_digest=source_digest,
    )


def normalize_source_image(config: MirrorConfig, image: str) -> str:
    if ":" not in image.rsplit("/", maxsplit=1)[-1]:
        image = f"{image}:latest"
    if image.startswith("docker.io/"):
        return f"{config.upstream_chart_registry}/{image.removeprefix('docker.io/')}"
    if image.startswith(f"{config.upstream_chart_registry}/"):
        return image
    return f"{config.upstream_chart_registry}/{image}"


def build_target_tag(app_version: str, os_flavour: str, image_revision: str) -> str:
    raw = f"{app_version}-{os_flavour}-r{image_revision}"
    return re.sub(r"[^0-9A-Za-z_.-]+", "-", raw)


def strip_tag(image: str) -> str:
    head, tail = image.rsplit("/", maxsplit=1)
    if ":" not in tail:
        return image
    return f"{head}/{tail.split(':', maxsplit=1)[0]}"


def parse_env(env_items: list[str]) -> dict[str, str]:
    return dict(item.split("=", maxsplit=1) for item in env_items)


def require_env(env: dict[str, str], key: str, image: str) -> str:
    if key not in env or env[key] == "":
        raise SyncError(f"{image} is missing required env {key}")
    return env[key]


def patch_chart_yaml(
    config: MirrorConfig,
    chart_yaml: dict[str, Any],
    chart_name: str,
    version: str,
    source_digest: str,
) -> None:
    for dependency in chart_yaml.get("dependencies", []):
        if dependency.get("repository") == f"oci://{config.upstream_chart_registry}/{config.upstream_chart_namespace}":
            dependency["repository"] = f"oci://{config.upstream_chart_registry}/{config.dockerhub_namespace}"

    annotations = chart_yaml.setdefault("annotations", {})
    annotations["inglp.bitnami-secure-mirror/source-chart"] = (
        f"{config.upstream_chart_registry}/{config.upstream_chart_namespace}/{chart_name}:{version}"
    )
    annotations["inglp.bitnami-secure-mirror/source-digest"] = source_digest


def patch_values_yaml(values: Any, mirrors: list[MirroredImage]) -> None:
    mirror_by_source_repo = {
        image.source_image.removesuffix(":latest"): image
        for image in mirrors
    }
    patch_image_maps(values, mirror_by_source_repo)
    if mirrors:
        enable_mirrored_image_repositories(values)


def enable_mirrored_image_repositories(values: Any) -> None:
    if not isinstance(values, dict):
        raise SyncError("values.yaml root must be a mapping")
    global_values = values.setdefault("global", {})
    if not isinstance(global_values, dict):
        raise SyncError("values.yaml global value must be a mapping")
    security_values = global_values.setdefault("security", {})
    if not isinstance(security_values, dict):
        raise SyncError("values.yaml global.security value must be a mapping")
    security_values["allowInsecureImages"] = True


def patch_image_maps(node: Any, mirror_by_source_repo: dict[str, MirroredImage]) -> None:
    if isinstance(node, dict):
        repository = node.get("repository")
        if isinstance(repository, str):
            mirror = find_repository_mirror(repository, mirror_by_source_repo)
            if mirror is not None:
                node["registry"] = mirror.target_registry
                node["repository"] = mirror.target_repository
                node["tag"] = mirror.target_tag
                node["digest"] = mirror.target_digest
        for value in node.values():
            patch_image_maps(value, mirror_by_source_repo)
    elif isinstance(node, list):
        for value in node:
            patch_image_maps(value, mirror_by_source_repo)


def find_repository_mirror(
    repository: str,
    mirror_by_source_repo: dict[str, MirroredImage],
) -> MirroredImage | None:
    normalized = normalize_repository(repository)
    for source_repo, mirror in mirror_by_source_repo.items():
        if normalize_repository(source_repo) == normalized:
            return mirror
    return None


def normalize_repository(repository: str) -> str:
    parts = repository.split("/")
    if parts[0] in {"docker.io", "registry-1.docker.io"}:
        parts = parts[1:]
    return "/".join(parts)


def build_dependencies(chart_dir: Path) -> None:
    chart_yaml = read_yaml(chart_dir / "Chart.yaml")
    if chart_yaml.get("dependencies"):
        run(["helm", "dependency", "build", str(chart_dir)])


def package_chart(chart_dir: Path, destination: Path) -> Path:
    output = run(["helm", "package", str(chart_dir), "--destination", str(destination)])
    for line in output.splitlines():
        marker = "Successfully packaged chart and saved it to: "
        if line.startswith(marker):
            return Path(line.removeprefix(marker))
    raise SyncError(f"Could not parse helm package output: {output}")


def write_lock(
    path: Path,
    chart_name: str,
    version: str,
    source_digest: str,
    mirrors: list[MirroredImage],
) -> None:
    payload = {
        "chart": chart_name,
        "version": version,
        "source_digest": source_digest,
        "images": [asdict(image) for image in mirrors],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def dockerhub_tag_digest(namespace: str, repository: str, tag: str) -> str:
    for item in dockerhub_tags(namespace, repository):
        if item["name"] == tag:
            return item["digest"]
    raise SyncError(f"Docker Hub tag not found: {namespace}/{repository}:{tag}")


def dockerhub_tags(namespace: str, repository: str) -> list[dict[str, Any]]:
    tags: list[dict[str, Any]] = []
    url = f"https://hub.docker.com/v2/namespaces/{namespace}/repositories/{repository}/tags?page_size=100"
    while url:
        payload = get_json(url)
        tags.extend(payload["results"])
        url = payload["next"]
    return tags


def list_available_repositories(namespace: str, content_type: str | None = None) -> list[str]:
    repositories: list[str] = []
    url = f"https://hub.docker.com/v2/namespaces/{namespace}/repositories?page_size=100"
    while url:
        payload = get_json(url)
        for item in payload["results"]:
            if content_type is None or content_type in item.get("content_types", []):
                repositories.append(item["name"])
        url = payload["next"]
    return sorted(repositories)


def skopeo_digest(image: str) -> str:
    return run([
        "skopeo",
        "inspect",
        "--override-os",
        "linux",
        "--override-arch",
        "amd64",
        "--format",
        "{{.Digest}}",
        f"docker://{image}",
    ]).strip()


def skopeo_config(image: str) -> dict[str, Any]:
    return json.loads(run([
        "skopeo",
        "inspect",
        "--override-os",
        "linux",
        "--override-arch",
        "amd64",
        "--config",
        f"docker://{image}",
    ]))


def get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def read_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def run(args: list[str]) -> str:
    completed = subprocess.run(args, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise SyncError(
            f"Command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed.stdout + completed.stderr


if __name__ == "__main__":
    sys.exit(main())
