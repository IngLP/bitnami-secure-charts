from __future__ import annotations

import pytest

from bitnami_secure_charts.cli import (
    MirroredImage,
    SyncError,
    build_target_tag,
    find_repository_mirror,
    parse_chart_images,
    parse_env,
    patch_chart_yaml,
    patch_values_yaml,
    require_env,
    strip_tag,
)
from bitnami_secure_charts.cli import MirrorConfig


class TestChartImages:
    def test_parse_chart_images_annotation(self) -> None:
        images = parse_chart_images(
            """
            - name: redis
              version: 8.6.3
              image: registry-1.docker.io/bitnamisecure/redis:latest
            """
        )

        assert images[0].name == "redis"
        assert images[0].version == "8.6.3"
        assert images[0].image == "registry-1.docker.io/bitnamisecure/redis:latest"


class TestImageTags:
    def test_build_target_tag(self) -> None:
        assert build_target_tag("18.3.0", "photon-5", "28") == "18.3.0-photon-5-r28"

    def test_parse_env(self) -> None:
        assert parse_env(["APP_VERSION=8.6.3", "IMAGE_REVISION=0"]) == {
            "APP_VERSION": "8.6.3",
            "IMAGE_REVISION": "0",
        }

    def test_require_env_fails_fast(self) -> None:
        with pytest.raises(SyncError, match="missing required env OS_FLAVOUR"):
            require_env({"APP_VERSION": "8.6.3"}, "OS_FLAVOUR", "redis")

    def test_strip_tag(self) -> None:
        assert strip_tag("registry-1.docker.io/bitnamisecure/redis:latest") == (
            "registry-1.docker.io/bitnamisecure/redis"
        )


class TestPatchValues:
    def test_patch_nested_image_maps(self) -> None:
        values = {
            "image": {"registry": "docker.io", "repository": "bitnamisecure/redis", "tag": "latest"},
            "sentinel": {
                "image": {
                    "registry": "docker.io",
                    "repository": "bitnamisecure/redis-sentinel",
                    "tag": "latest",
                }
            },
        }
        mirrors = [
            mirrored("redis", "8.6.3-photon-5-r0"),
            mirrored("redis-sentinel", "8.6.3-photon-5-r0"),
        ]

        patch_values_yaml(values, mirrors)

        assert values == {
            "global": {"security": {"allowInsecureImages": True}},
            "image": {
                "registry": "docker.io",
                "repository": "inglp/bitnami-secure-redis",
                "tag": "8.6.3-photon-5-r0",
                "digest": "sha256:redis",
            },
            "sentinel": {
                "image": {
                    "registry": "docker.io",
                    "repository": "inglp/bitnami-secure-redis-sentinel",
                    "tag": "8.6.3-photon-5-r0",
                    "digest": "sha256:redis-sentinel",
                }
            },
        }

    def test_find_repository_mirror_ignores_registry_prefix(self) -> None:
        mirror = mirrored("postgresql", "18.3.0-photon-5-r28")
        assert find_repository_mirror(
            "registry-1.docker.io/bitnamisecure/postgresql",
            {"registry-1.docker.io/bitnamisecure/postgresql": mirror},
        ) == mirror


class TestPatchChartYaml:
    def test_patch_dependency_repository_and_annotations(self) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("redis",),
        )
        chart_yaml = {
            "dependencies": [
                {"name": "common", "repository": "oci://registry-1.docker.io/bitnamichartssecure"}
            ],
            "annotations": {},
        }

        patch_chart_yaml(config, chart_yaml, "redis", "25.5.2", "sha256:chart")

        assert chart_yaml["dependencies"] == [
            {"name": "common", "repository": "oci://registry-1.docker.io/inglp"}
        ]
        assert chart_yaml["annotations"][
            "inglp.bitnami-secure-mirror/source-chart"
        ] == "registry-1.docker.io/bitnamichartssecure/redis:25.5.2"
        assert chart_yaml["annotations"]["inglp.bitnami-secure-mirror/source-digest"] == "sha256:chart"


def mirrored(name: str, tag: str) -> MirroredImage:
    return MirroredImage(
        name=name,
        source_image=f"registry-1.docker.io/bitnamisecure/{name}:latest",
        source_digest=f"sha256:{name}",
        app_version=tag.split("-", maxsplit=1)[0],
        os_flavour="photon-5",
        image_revision="0",
        target_registry="docker.io",
        target_repository=f"inglp/bitnami-secure-{name}",
        target_tag=tag,
        target_digest=f"sha256:{name}",
    )
