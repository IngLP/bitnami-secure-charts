from __future__ import annotations

import io
import json
import tarfile
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import AbstractContextManager, nullcontext
from typing import Any

import pytest

from bitnami_secure_charts.cli import (
    ChartImage,
    ChartSelection,
    DockerHubRedirectHandler,
    MirroredDependency,
    MirroredChartVersion,
    MirroredImage,
    MirrorConfig,
    PACKAGE_MTIME,
    SyncError,
    build_content_fingerprint,
    build_mirror_chart_version,
    build_target_tag,
    chart_lock_path,
    confirm_published,
    compute_lock_published,
    compute_mirror_version,
    dependency_closure_order,
    dependency_lock_key,
    dockerhub_access_token,
    dockerhub_get_json,
    dockerhub_opener,
    dockerhub_tags,
    find_repository_mirror,
    inspect_image,
    list_available_repositories,
    load_chart_dependency_selections,
    normalize_chart_package_mtimes,
    parse_chart_images,
    parse_env,
    patch_chart_yaml,
    patch_values_yaml,
    require_env,
    resolve_mirrored_dependencies,
    should_publish_chart,
    strip_tag,
    sync_chart,
    vendor_dependencies,
)


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

    def test_exporter_without_os_or_revision_gets_stable_digest_tag(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("memcached",),
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.skopeo_digest",
            lambda image: "sha256:abcdef1234567890",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.skopeo_config",
            lambda image: {"config": {"Env": ["APP_VERSION=0.15.3"]}},
        )

        image = inspect_image(
            config,
            ChartImage(
                name="memcached-exporter",
                version="0.15.3",
                image="registry-1.docker.io/bitnamisecure/memcached-exporter:latest",
            ),
        )

        assert image.target_tag == "0.15.3-linux-rdigest-abcdef123456"
        assert image.os_flavour == "linux"
        assert image.image_revision == "digest-abcdef123456"


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
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
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

        patch_chart_yaml(
            config=config,
            chart_yaml=chart_yaml,
            chart_name="redis",
            upstream_version="25.5.2",
            source_digest="sha256:chart",
            mirror_version="25.5.2-inglp.r0",
            mirrored_dependencies=[
                MirroredDependency(
                    name="common",
                    repository="https://inglp.github.io/bitnami-secure-charts",
                    upstream_version="2.39.0",
                    version="2.39.0-inglp.r0",
                )
            ],
        )

        assert chart_yaml["version"] == "25.5.2-inglp.r0"
        assert chart_yaml["dependencies"] == [
            {
                "name": "common",
                "repository": "https://inglp.github.io/bitnami-secure-charts",
                "version": "2.39.0-inglp.r0",
            }
        ]
        assert chart_yaml["annotations"][
            "inglp.bitnami-secure-mirror/source-chart"
        ] == "registry-1.docker.io/bitnamichartssecure/redis:25.5.2"
        assert chart_yaml["annotations"]["inglp.bitnami-secure-mirror/source-digest"] == "sha256:chart"
        assert chart_yaml["annotations"]["inglp.bitnami-secure-mirror/upstream-version"] == "25.5.2"

    def test_resolve_mirrored_dependencies_fails_without_mirrored_lock(self) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("redis",),
        )
        chart_yaml = {
            "name": "redis",
            "dependencies": [
                {
                    "name": "common",
                    "repository": "oci://registry-1.docker.io/bitnamichartssecure",
                    "version": "2.39.0",
                }
            ],
        }

        with pytest.raises(SyncError, match="redis depends on common"):
            resolve_mirrored_dependencies(config, chart_yaml, {})

    def test_resolve_mirrored_dependencies_fails_on_upstream_version_mismatch(self) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("wordpress",),
        )
        chart_yaml = {
            "name": "wordpress",
            "dependencies": [
                {
                    "name": "mariadb",
                    "repository": "oci://registry-1.docker.io/bitnamichartssecure",
                    "version": "25.1.1",
                }
            ],
        }

        with pytest.raises(SyncError, match="lock has upstream 25.2.0"):
            resolve_mirrored_dependencies(
                config,
                chart_yaml,
                {
                    dependency_lock_key("mariadb", "25.1.1"): MirroredChartVersion(
                        upstream_version="25.2.0",
                        version="25.2.0-inglp.r0",
                    )
                },
            )

    def test_resolve_mirrored_dependencies_uses_locked_upstream_versions(self) -> None:
        config = mirror_config(("redis", "common"))
        chart_yaml = {
            "name": "redis",
            "dependencies": [
                {
                    "name": "common",
                    "repository": "https://inglp.github.io/bitnami-secure-charts",
                    "version": "2.39.0-inglp.r0",
                }
            ],
        }

        assert resolve_mirrored_dependencies(
            config,
            chart_yaml,
            {
                dependency_lock_key("common", "2.39.0"): MirroredChartVersion(
                    upstream_version="2.39.0",
                    version="2.39.0-inglp.r0",
                )
            },
            (ChartSelection("common", "2.39.0"),),
        ) == [mirrored_dependency("common", "2.39.0", "2.39.0-inglp.r0")]


class TestMirrorVersion:
    def test_build_mirror_chart_version_for_plain_semver(self) -> None:
        assert build_mirror_chart_version("25.5.2", 1) == "25.5.2-inglp.r1"

    def test_build_mirror_chart_version_for_prerelease_semver(self) -> None:
        assert build_mirror_chart_version("25.5.2-beta.1", 2) == "25.5.2-beta.1.inglp.r2"

    def test_build_mirror_chart_version_encodes_build_metadata_without_plus(self) -> None:
        assert build_mirror_chart_version("25.5.2+build.7", 0) == "25.5.2-inglp.meta.build.7.r0"

    def test_compute_mirror_version_reuses_unchanged_content(self) -> None:
        previous_lock = {
            "upstream_version": "25.5.2",
            "content_fingerprint": "sha256:fingerprint",
            "mirror_revision": 3,
            "version": "25.5.2-inglp.r3",
        }

        version, revision, changed = compute_mirror_version(
            upstream_version="25.5.2",
            content_fingerprint="sha256:fingerprint",
            previous_lock=previous_lock,
        )

        assert version == "25.5.2-inglp.r3"
        assert revision == 3
        assert changed is False

    def test_compute_mirror_version_increments_same_upstream_changed_content(self) -> None:
        previous_lock = {
            "upstream_version": "25.5.2",
            "content_fingerprint": "sha256:old",
            "mirror_revision": 3,
            "version": "25.5.2-inglp.r3",
        }

        version, revision, changed = compute_mirror_version(
            upstream_version="25.5.2",
            content_fingerprint="sha256:new",
            previous_lock=previous_lock,
        )

        assert version == "25.5.2-inglp.r4"
        assert revision == 4
        assert changed is True

    def test_compute_mirror_version_resets_on_new_upstream_version(self) -> None:
        previous_lock = {
            "upstream_version": "25.5.2",
            "content_fingerprint": "sha256:old",
            "mirror_revision": 3,
            "version": "25.5.2-inglp.r3",
        }

        version, revision, changed = compute_mirror_version(
            upstream_version="25.5.3",
            content_fingerprint="sha256:new",
            previous_lock=previous_lock,
        )

        assert version == "25.5.3-inglp.r0"
        assert revision == 0
        assert changed is True

    def test_content_fingerprint_changes_when_image_digest_changes(self) -> None:
        first = build_content_fingerprint("sha256:chart", [mirrored("redis", "8.6.3-photon-5-r0")], [])
        second_image = mirrored("redis", "8.6.3-photon-5-r0")
        second_image = MirroredImage(
            **{
                **second_image.__dict__,
                "source_digest": "sha256:redis2",
                "target_digest": "sha256:redis2",
            }
        )
        second = build_content_fingerprint("sha256:chart", [second_image], [])

        assert first != second

    def test_common_dependency_change_increments_dependent_chart_revision(self) -> None:
        old_fingerprint = build_content_fingerprint(
            "sha256:chart",
            [],
            [mirrored_dependency("common", "2.39.0", "2.39.0-inglp.r0")],
        )
        new_fingerprint = build_content_fingerprint(
            "sha256:chart",
            [],
            [mirrored_dependency("common", "2.39.0", "2.39.0-inglp.r1")],
        )

        version, revision, changed = compute_mirror_version(
            upstream_version="25.5.2",
            content_fingerprint=new_fingerprint,
            previous_lock={
                "upstream_version": "25.5.2",
                "content_fingerprint": old_fingerprint,
                "mirror_revision": 0,
                "version": "25.5.2-inglp.r0",
            },
        )

        assert version == "25.5.2-inglp.r1"
        assert revision == 1
        assert changed is True

    def test_content_fingerprint_changes_when_target_repository_changes(self) -> None:
        first = build_content_fingerprint("sha256:chart", [mirrored("redis", "8.6.3-photon-5-r0")], [])
        second_image = mirrored("redis", "8.6.3-photon-5-r0")
        second_image = MirroredImage(
            **{
                **second_image.__dict__,
                "target_repository": "other/bitnami-secure-redis",
            }
        )
        second = build_content_fingerprint("sha256:chart", [second_image], [])

        assert first != second


class TestLocks:
    def test_chart_lock_path_includes_upstream_version(self, tmp_path) -> None:
        assert chart_lock_path(tmp_path, "mariadb", "25.1.1") == tmp_path / "mariadb-25.1.1.json"


class TestSyncOrdering:
    def test_dependency_closure_orders_recursive_dependencies_first(self) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("common", "mariadb", "wordpress"),
        )
        dependencies = {
            ChartSelection("wordpress", "30.1.1"): (
                ChartSelection("mariadb", "25.1.1"),
                ChartSelection("common", "2.39.0"),
            ),
            ChartSelection("mariadb", "25.1.1"): (ChartSelection("common", "2.39.0"),),
            ChartSelection("common", "2.39.0"): (),
        }

        assert dependency_closure_order(
            config,
            (ChartSelection("wordpress", "30.1.1"),),
            dependencies.__getitem__,
        ) == (
            ChartSelection("common", "2.39.0"),
            ChartSelection("mariadb", "25.1.1"),
            ChartSelection("wordpress", "30.1.1"),
        )

    def test_dependency_closure_detects_cycles(self) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("redis", "common"),
        )
        dependencies = {
            ChartSelection("redis", "25.5.2"): (ChartSelection("common", "2.39.0"),),
            ChartSelection("common", "2.39.0"): (ChartSelection("redis", "25.5.2"),),
        }

        with pytest.raises(SyncError, match="cycle"):
            dependency_closure_order(config, (ChartSelection("redis", "25.5.2"),), dependencies.__getitem__)

    def test_dependency_closure_allows_multiple_pinned_versions_of_same_chart(self) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("common", "mariadb", "wordpress"),
        )
        dependencies = {
            ChartSelection("wordpress", "30.1.1"): (
                ChartSelection("mariadb", "25.1.1"),
                ChartSelection("common", "2.39.0"),
            ),
            ChartSelection("mariadb", "25.1.1"): (ChartSelection("common", "2.40.0"),),
            ChartSelection("common", "2.39.0"): (),
            ChartSelection("common", "2.40.0"): (),
        }

        assert dependency_closure_order(
            config,
            (ChartSelection("wordpress", "30.1.1"),),
            dependencies.__getitem__,
        ) == (
            ChartSelection("common", "2.40.0"),
            ChartSelection("mariadb", "25.1.1"),
            ChartSelection("common", "2.39.0"),
            ChartSelection("wordpress", "30.1.1"),
        )

    def test_patched_local_chart_dependencies_come_from_matching_lock(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = mirror_config(("redis", "common"))
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        chart_dir = charts_dir / "redis"
        chart_dir.mkdir(parents=True)
        locks_dir.mkdir()
        (chart_dir / "Chart.yaml").write_text(
            """
            name: redis
            version: 25.5.2-inglp.r0
            annotations:
              inglp.bitnami-secure-mirror/upstream-version: 25.5.2
            dependencies:
              - name: common
                repository: https://inglp.github.io/bitnami-secure-charts
                version: 2.39.0-inglp.r0
            """,
            encoding="utf-8",
        )
        chart_lock_path(locks_dir, "redis", "25.5.2").write_text(
            json_lock(
                chart="redis",
                upstream_version="25.5.2",
                version="25.5.2-inglp.r0",
                mirror_revision=0,
                content_fingerprint="sha256:fingerprint",
                source_digest="sha256:redis-chart",
                published=True,
                dependencies=[
                    {
                        "name": "common",
                        "repository": "https://inglp.github.io/bitnami-secure-charts",
                        "upstream_version": "2.39.0",
                        "version": "2.39.0-inglp.r0",
                    }
                ],
                images=[],
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:redis-chart",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.upstream_chart_metadata",
            lambda config, chart_name, version: pytest.fail("should use matching lock"),
        )

        assert load_chart_dependency_selections(
            config,
            ChartSelection("redis", "25.5.2"),
            charts_dir,
            locks_dir,
        ) == (ChartSelection("common", "2.39.0"),)

    def test_changed_upstream_digest_ignores_stale_lock_dependencies(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = mirror_config(("redis", "common"))
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        charts_dir.mkdir()
        locks_dir.mkdir()
        chart_lock_path(locks_dir, "redis", "25.5.2").write_text(
            json_lock(
                chart="redis",
                upstream_version="25.5.2",
                version="25.5.2-inglp.r0",
                mirror_revision=0,
                content_fingerprint="sha256:fingerprint",
                source_digest="sha256:old-redis-chart",
                published=True,
                dependencies=[
                    {
                        "name": "common",
                        "repository": "https://inglp.github.io/bitnami-secure-charts",
                        "upstream_version": "2.39.0",
                        "version": "2.39.0-inglp.r0",
                    }
                ],
                images=[],
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:new-redis-chart",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.upstream_chart_metadata",
            lambda config, chart_name, version: {
                "dependencies": [
                    {
                        "name": "common",
                        "repository": "oci://registry-1.docker.io/bitnamichartssecure",
                        "version": "2.40.0",
                    }
                ]
            },
        )

        assert load_chart_dependency_selections(
            config,
            ChartSelection("redis", "25.5.2"),
            charts_dir,
            locks_dir,
        ) == (ChartSelection("common", "2.40.0"),)

    def test_matching_lock_dependencies_are_filtered_by_allowlist(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = mirror_config(("redis", "common"))
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        charts_dir.mkdir()
        locks_dir.mkdir()
        chart_lock_path(locks_dir, "redis", "25.5.2").write_text(
            json_lock(
                chart="redis",
                upstream_version="25.5.2",
                version="25.5.2-inglp.r0",
                mirror_revision=0,
                content_fingerprint="sha256:fingerprint",
                source_digest="sha256:redis-chart",
                published=True,
                dependencies=[
                    {
                        "name": "common",
                        "repository": "https://inglp.github.io/bitnami-secure-charts",
                        "upstream_version": "2.39.0",
                        "version": "2.39.0-inglp.r0",
                    },
                    {
                        "name": "mysql",
                        "repository": "https://inglp.github.io/bitnami-secure-charts",
                        "upstream_version": "13.0.0",
                        "version": "13.0.0-inglp.r0",
                    },
                ],
                images=[],
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:redis-chart",
        )

        assert load_chart_dependency_selections(
            config,
            ChartSelection("redis", "25.5.2"),
            charts_dir,
            locks_dir,
        ) == (ChartSelection("common", "2.39.0"),)

    def test_malformed_matching_lock_dependency_fails_fast(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = mirror_config(("redis", "common"))
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        charts_dir.mkdir()
        locks_dir.mkdir()
        chart_lock_path(locks_dir, "redis", "25.5.2").write_text(
            json_lock(
                chart="redis",
                upstream_version="25.5.2",
                version="25.5.2-inglp.r0",
                mirror_revision=0,
                content_fingerprint="sha256:fingerprint",
                source_digest="sha256:redis-chart",
                published=True,
                dependencies=[
                    {
                        "name": "common",
                        "repository": "https://inglp.github.io/bitnami-secure-charts",
                        "version": "2.39.0-inglp.r0",
                    }
                ],
                images=[],
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:redis-chart",
        )

        with pytest.raises(SyncError, match="Malformed dependency"):
            load_chart_dependency_selections(
                config,
                ChartSelection("redis", "25.5.2"),
                charts_dir,
                locks_dir,
            )

    def test_non_mapping_matching_lock_dependency_fails_fast(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = mirror_config(("redis", "common"))
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        charts_dir.mkdir()
        locks_dir.mkdir()
        chart_lock_path(locks_dir, "redis", "25.5.2").write_text(
            json_lock(
                chart="redis",
                upstream_version="25.5.2",
                version="25.5.2-inglp.r0",
                mirror_revision=0,
                content_fingerprint="sha256:fingerprint",
                source_digest="sha256:redis-chart",
                published=True,
                dependencies=["common"],
                images=[],
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:redis-chart",
        )

        with pytest.raises(SyncError, match="Malformed dependency"):
            load_chart_dependency_selections(
                config,
                ChartSelection("redis", "25.5.2"),
                charts_dir,
                locks_dir,
            )


class TestPublishState:
    def test_dry_sync_new_content_marks_lock_unpublished(self) -> None:
        previous_lock = {
            "published": True,
        }

        assert should_publish_chart(push=False, content_changed=True, previous_lock=previous_lock) is False
        assert compute_lock_published(push=False, content_changed=True, previous_lock=previous_lock) is False

    def test_push_after_dry_sync_stages_without_marking_published(self) -> None:
        previous_lock = {
            "published": False,
        }

        assert should_publish_chart(push=True, content_changed=False, previous_lock=previous_lock) is True
        assert compute_lock_published(
            push=True,
            content_changed=False,
            previous_lock=previous_lock,
            staged_for_publication=True,
        ) is False

    def test_push_skips_when_same_content_was_already_published(self) -> None:
        previous_lock = {
            "published": True,
        }

        assert should_publish_chart(push=True, content_changed=False, previous_lock=previous_lock) is False
        assert compute_lock_published(push=True, content_changed=False, previous_lock=previous_lock) is True

    def test_push_still_packages_unchanged_published_chart(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("common",),
        )
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        package_dir = tmp_path / "dist"
        charts_dir.mkdir()
        locks_dir.mkdir()
        package_dir.mkdir()
        fingerprint = build_content_fingerprint("sha256:chart", [], [])
        chart_lock_path(locks_dir, "common", "2.39.0").write_text(
            json_lock(
                chart="common",
                upstream_version="2.39.0",
                version="2.39.0-inglp.r0",
                mirror_revision=0,
                content_fingerprint=fingerprint,
                source_digest="sha256:chart",
                published=True,
                dependencies=[],
                images=[],
            ),
            encoding="utf-8",
        )

        def fake_run(args: list[str]) -> str:
            if args[:2] == ["helm", "pull"]:
                chart_dir = charts_dir / "common"
                chart_dir.mkdir()
                (chart_dir / "Chart.yaml").write_text(
                    "name: common\nversion: 2.39.0\nannotations:\n  images: '[]'\n",
                    encoding="utf-8",
                )
                (chart_dir / "values.yaml").write_text("{}\n", encoding="utf-8")
                return ""
            if args[:2] == ["helm", "package"]:
                package_path = package_dir / "common-2.39.0-inglp.r0.tgz"
                package_path.write_bytes(b"chart")
                return f"Successfully packaged chart and saved it to: {package_path}\n"
            raise AssertionError(f"unexpected command: {args}")

        monkeypatch.setattr("bitnami_secure_charts.cli.run", fake_run)
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:chart",
        )

        sync_chart(
            config=config,
            chart_name="common",
            version="2.39.0",
            charts_dir=charts_dir,
            locks_dir=locks_dir,
            package_dir=package_dir,
            push=True,
            copied_images=set(),
        )

        assert (package_dir / "common-2.39.0-inglp.r0.tgz").exists()
        assert not (package_dir / "publish" / "common-2.39.0-inglp.r0.tgz").exists()

    def test_push_stages_new_chart_package_for_publication(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = MirrorConfig(
            dockerhub_namespace="inglp",
            chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
            upstream_chart_registry="registry-1.docker.io",
            upstream_chart_namespace="bitnamichartssecure",
            upstream_image_registry="registry-1.docker.io",
            upstream_image_namespace="bitnamisecure",
            target_image_prefix="bitnami-secure-",
            chart_names=("common",),
        )
        charts_dir = tmp_path / "charts"
        locks_dir = tmp_path / "locks"
        package_dir = tmp_path / "dist"
        charts_dir.mkdir()
        locks_dir.mkdir()
        package_dir.mkdir()

        def fake_run(args: list[str]) -> str:
            if args[:2] == ["helm", "pull"]:
                chart_dir = charts_dir / "common"
                chart_dir.mkdir()
                (chart_dir / "Chart.yaml").write_text(
                    "name: common\nversion: 2.39.0\nannotations:\n  images: '[]'\n",
                    encoding="utf-8",
                )
                (chart_dir / "values.yaml").write_text("{}\n", encoding="utf-8")
                return ""
            if args[:2] == ["helm", "package"]:
                package_path = package_dir / "common-2.39.0-inglp.r0.tgz"
                package_path.write_bytes(b"chart")
                return f"Successfully packaged chart and saved it to: {package_path}\n"
            raise AssertionError(f"unexpected command: {args}")

        monkeypatch.setattr("bitnami_secure_charts.cli.run", fake_run)
        monkeypatch.setattr(
            "bitnami_secure_charts.cli.dockerhub_tag_digest",
            lambda namespace, repository, tag: "sha256:chart",
        )

        sync_chart(
            config=config,
            chart_name="common",
            version="2.39.0",
            charts_dir=charts_dir,
            locks_dir=locks_dir,
            package_dir=package_dir,
            push=True,
            copied_images=set(),
        )

        assert (package_dir / "common-2.39.0-inglp.r0.tgz").exists()
        assert (package_dir / "publish" / "common-2.39.0-inglp.r0.tgz").exists()
        assert read_json(chart_lock_path(locks_dir, "common", "2.39.0"))["published"] is False


class TestVendorDependencies:
    def test_vendor_dependencies_copies_built_dependency_package(self, tmp_path) -> None:
        chart_dir = tmp_path / "redis"
        package_dir = tmp_path / "dist"
        chart_dir.mkdir()
        package_dir.mkdir()
        (chart_dir / "Chart.yaml").write_text("name: redis\ndependencies: []\n", encoding="utf-8")
        package_path = package_dir / "common-2.39.0-inglp.r0.tgz"
        with tarfile.open(package_path, "w:gz"):
            pass

        vendor_dependencies(
            chart_dir,
            package_dir,
            [mirrored_dependency("common", "2.39.0", "2.39.0-inglp.r0")],
        )

        assert (chart_dir / "charts" / "common-2.39.0-inglp.r0.tgz").exists()

    def test_vendor_dependencies_fails_when_package_is_missing(self, tmp_path) -> None:
        chart_dir = tmp_path / "redis"
        package_dir = tmp_path / "dist"
        chart_dir.mkdir()
        package_dir.mkdir()
        (chart_dir / "Chart.yaml").write_text("name: redis\ndependencies: []\n", encoding="utf-8")

        with pytest.raises(SyncError, match="common-2.39.0-inglp.r0.tgz"):
            vendor_dependencies(
                chart_dir,
                package_dir,
                [mirrored_dependency("common", "2.39.0", "2.39.0-inglp.r0")],
            )


class TestPackageChart:
    def test_normalize_chart_package_mtimes_sets_stable_timestamp(self, tmp_path) -> None:
        chart_dir = tmp_path / "redis"
        templates_dir = chart_dir / "templates"
        templates_dir.mkdir(parents=True)
        chart_file = chart_dir / "Chart.yaml"
        template_file = templates_dir / "deployment.yaml"
        chart_file.write_text("name: redis\n", encoding="utf-8")
        template_file.write_text("kind: Deployment\n", encoding="utf-8")

        normalize_chart_package_mtimes(chart_dir)

        assert int(chart_dir.stat().st_mtime) == PACKAGE_MTIME
        assert int(templates_dir.stat().st_mtime) == PACKAGE_MTIME
        assert int(chart_file.stat().st_mtime) == PACKAGE_MTIME
        assert int(template_file.stat().st_mtime) == PACKAGE_MTIME


class TestConfirmPublished:
    def test_confirm_published_marks_staged_package_lock(self, tmp_path) -> None:
        locks_dir = tmp_path / "locks"
        package_dir = tmp_path / "dist" / "publish"
        locks_dir.mkdir()
        package_dir.mkdir(parents=True)
        chart_lock_path(locks_dir, "common", "2.39.0").write_text(
            json_lock(
                chart="common",
                upstream_version="2.39.0",
                version="2.39.0-inglp.r0",
                mirror_revision=0,
                content_fingerprint="sha256:fingerprint",
                source_digest="sha256:chart",
                published=False,
                dependencies=[],
                images=[],
            ),
            encoding="utf-8",
        )
        write_chart_package(package_dir / "common-2.39.0-inglp.r0.tgz", "common", "2.39.0-inglp.r0")

        confirm_published(locks_dir, package_dir)

        assert read_json(chart_lock_path(locks_dir, "common", "2.39.0"))["published"] is True

    def test_confirm_published_fails_without_matching_lock(self, tmp_path) -> None:
        locks_dir = tmp_path / "locks"
        package_dir = tmp_path / "dist" / "publish"
        locks_dir.mkdir()
        package_dir.mkdir(parents=True)
        write_chart_package(package_dir / "redis-25.5.2-inglp.r0.tgz", "redis", "25.5.2-inglp.r0")

        with pytest.raises(SyncError, match="No lock found"):
            confirm_published(locks_dir, package_dir)


class TestDockerHubApi:
    @pytest.fixture(autouse=True)
    def clear_cached_token(self) -> Iterator[None]:
        dockerhub_access_token.cache_clear()
        dockerhub_tags.cache_clear()
        yield
        dockerhub_access_token.cache_clear()
        dockerhub_tags.cache_clear()

    def test_access_token_posts_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(monkeypatch, [{"access_token": "jwt-first"}])

        assert dockerhub_access_token() == "jwt-first"
        assert requests[0].full_url == TOKEN_URL
        assert requests[0].get_method() == "POST"
        assert json.loads(requests[0].data.decode("utf-8")) == {
            "identifier": "inglp",
            "secret": "dckr_pat_secret",
        }
        assert requests[0].get_header("Content-type") == "application/json"

    @pytest.mark.parametrize(
        ("username", "token"),
        [("", "dckr_pat_secret"), ("inglp", ""), ("", "")],
    )
    def test_access_token_fails_fast_without_credentials(
        self,
        monkeypatch: pytest.MonkeyPatch,
        username: str,
        token: str,
    ) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", username)
        monkeypatch.setenv("DOCKERHUB_TOKEN", token)

        with pytest.raises(SyncError, match="set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN"):
            dockerhub_access_token()

    def test_tag_pages_are_all_fetched_with_the_bearer_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        second_page = "https://hub.docker.com/v2/namespaces/bitnamichartssecure/repositories/redis/tags?page=2&page_size=100"
        requests = record_urlopen(
            monkeypatch,
            [
                {"access_token": "jwt-first"},
                {"results": [{"name": "28.0.2", "content_type": "helm"}], "next": second_page},
                {"results": [{"name": "28.0.1", "content_type": "helm"}], "next": None},
            ],
        )

        assert dockerhub_tags("bitnamichartssecure", "redis") == [
            {"name": "28.0.2", "content_type": "helm"},
            {"name": "28.0.1", "content_type": "helm"},
        ]
        assert [request.full_url for request in requests] == [TOKEN_URL, TAGS_URL, second_page]
        assert requests[1].get_header("Authorization") == "Bearer jwt-first"
        assert requests[2].get_header("Authorization") == "Bearer jwt-first"

    def test_repository_pages_are_all_fetched_with_the_bearer_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        first_page = "https://hub.docker.com/v2/namespaces/bitnamichartssecure/repositories?page_size=100"
        second_page = "https://hub.docker.com/v2/namespaces/bitnamichartssecure/repositories?page=2&page_size=100"
        requests = record_urlopen(
            monkeypatch,
            [
                {"access_token": "jwt-first"},
                {
                    "results": [
                        {"name": "redis", "content_types": ["helm"]},
                        {"name": "charts-index", "content_types": ["image"]},
                    ],
                    "next": second_page,
                },
                {"results": [{"name": "common", "content_types": ["helm"]}], "next": None},
            ],
        )

        assert list_available_repositories("bitnamichartssecure", content_type="helm") == [
            "common",
            "redis",
        ]
        assert [request.full_url for request in requests] == [TOKEN_URL, first_page, second_page]
        assert requests[2].get_header("Authorization") == "Bearer jwt-first"

    @pytest.mark.parametrize(
        "hostile_next",
        [
            "https://evil.example.com/v2/namespaces/bitnamichartssecure/repositories/redis/tags",
            "http://hub.docker.com/v2/namespaces/bitnamichartssecure/repositories/redis/tags",
            "https://hub.docker.com.evil.example.com/v2/tags",
        ],
    )
    def test_paginated_next_off_the_api_origin_never_gets_the_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hostile_next: str,
    ) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(
            monkeypatch,
            [
                {"access_token": "jwt-first"},
                {"results": [{"name": "28.0.2"}], "next": hostile_next},
            ],
        )

        with pytest.raises(SyncError, match="Refusing to send Docker Hub credentials"):
            dockerhub_tags("bitnamichartssecure", "redis")

        assert [request.full_url for request in requests] == [TOKEN_URL, TAGS_URL]

    def test_opener_replaces_the_permissive_redirect_handler(self) -> None:
        """The guard only bites if the real opener carries it and nothing else."""
        redirect_handlers = [
            handler
            for handler in dockerhub_opener().handlers
            if isinstance(handler, urllib.request.HTTPRedirectHandler)
        ]

        assert [type(handler) for handler in redirect_handlers] == [DockerHubRedirectHandler]

    def test_redirect_off_the_api_origin_is_refused(self) -> None:
        handler = DockerHubRedirectHandler()
        request = urllib.request.Request(TAGS_URL, headers={"Authorization": "Bearer jwt-first"})

        with pytest.raises(SyncError, match="Refusing to send Docker Hub credentials"):
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://evil.example.com/v2/tags"
            )

    def test_redirect_inside_the_api_origin_keeps_the_bearer_token(self) -> None:
        handler = DockerHubRedirectHandler()
        request = urllib.request.Request(TAGS_URL, headers={"Authorization": "Bearer jwt-first"})
        redirected = "https://hub.docker.com/v2/namespaces/bitnamichartssecure/repositories/redis/tags?page=2"

        followed = handler.redirect_request(request, None, 302, "Found", {}, redirected)

        assert followed is not None
        assert followed.full_url == redirected
        assert followed.get_header("Authorization") == "Bearer jwt-first"

    def test_get_json_sends_bearer_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(
            monkeypatch,
            [{"access_token": "jwt-first"}, {"results": [{"name": "25.5.2"}], "next": None}],
        )

        assert dockerhub_get_json(TAGS_URL) == {"results": [{"name": "25.5.2"}], "next": None}
        assert requests[1].full_url == TAGS_URL
        assert requests[1].get_header("Authorization") == "Bearer jwt-first"

    def test_expired_token_is_refreshed_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(
            monkeypatch,
            [
                {"access_token": "jwt-expired"},
                http_error(401),
                {"access_token": "jwt-fresh"},
                {"results": [{"name": "25.5.2"}], "next": None},
            ],
        )

        assert dockerhub_get_json(TAGS_URL) == {"results": [{"name": "25.5.2"}], "next": None}
        assert [request.full_url for request in requests] == [
            TOKEN_URL,
            TAGS_URL,
            TOKEN_URL,
            TAGS_URL,
        ]
        assert requests[1].get_header("Authorization") == "Bearer jwt-expired"
        assert requests[3].get_header("Authorization") == "Bearer jwt-fresh"

    def test_rejected_credentials_are_not_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A token endpoint that rejects the PAT is a dead end, not an expired token."""
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_revoked")
        requests = record_urlopen(monkeypatch, [http_error(401, TOKEN_URL)])

        with pytest.raises(urllib.error.HTTPError) as raised:
            dockerhub_get_json(TAGS_URL)

        assert raised.value.code == 401
        assert [request.full_url for request in requests] == [TOKEN_URL]

    def test_token_is_refreshed_at_most_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(
            monkeypatch,
            [
                {"access_token": "jwt-expired"},
                http_error(401),
                {"access_token": "jwt-fresh"},
                http_error(401),
            ],
        )

        with pytest.raises(urllib.error.HTTPError) as raised:
            dockerhub_get_json(TAGS_URL)

        assert raised.value.code == 401
        assert len(requests) == 4

    def test_forbidden_response_is_not_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(monkeypatch, [{"access_token": "jwt-first"}, http_error(403)])

        with pytest.raises(urllib.error.HTTPError) as raised:
            dockerhub_get_json(TAGS_URL)

        assert raised.value.code == 403
        assert len(requests) == 2

    def test_repeated_calls_reuse_the_cached_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DOCKERHUB_USERNAME", "inglp")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "dckr_pat_secret")
        requests = record_urlopen(
            monkeypatch,
            [
                {"access_token": "jwt-first"},
                {"results": [], "next": None},
                {"results": [], "next": None},
            ],
        )

        dockerhub_get_json(TAGS_URL)
        dockerhub_get_json(TAGS_URL)

        assert [request.full_url for request in requests] == [
            TOKEN_URL,
            TAGS_URL,
            TAGS_URL,
        ]


TOKEN_URL = "https://hub.docker.com/v2/auth/token"
TAGS_URL = "https://hub.docker.com/v2/namespaces/bitnamichartssecure/repositories/redis/tags?page_size=100"


def http_error(code: int, url: str = TAGS_URL) -> urllib.error.HTTPError:
    reasons = {401: "Unauthorized", 403: "Forbidden"}
    return urllib.error.HTTPError(url, code, reasons[code], {}, None)


def record_urlopen(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[dict[str, Any] | urllib.error.HTTPError],
) -> list[urllib.request.Request]:
    """Serve `responses` in order to the Docker Hub opener and collect its requests.

    Wiring of the real opener is covered separately by
    `test_opener_replaces_the_permissive_redirect_handler`.
    """
    remaining = list(responses)
    requests: list[urllib.request.Request] = []

    def fake_open(request: urllib.request.Request, timeout: int) -> AbstractContextManager[io.BytesIO]:
        assert remaining, f"unexpected request to {request.full_url}"
        assert timeout == 30
        requests.append(request)
        response = remaining.pop(0)
        if isinstance(response, urllib.error.HTTPError):
            raise response
        return nullcontext(io.BytesIO(json.dumps(response).encode("utf-8")))

    opener = urllib.request.build_opener(DockerHubRedirectHandler)
    monkeypatch.setattr(opener, "open", fake_open)
    monkeypatch.setattr("bitnami_secure_charts.cli.dockerhub_opener", lambda: opener)
    return requests


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


def mirrored_dependency(name: str, upstream_version: str, version: str) -> MirroredDependency:
    return MirroredDependency(
        name=name,
        repository="https://inglp.github.io/bitnami-secure-charts",
        upstream_version=upstream_version,
        version=version,
    )


def mirror_config(chart_names: tuple[str, ...]) -> MirrorConfig:
    return MirrorConfig(
        dockerhub_namespace="inglp",
        chart_repository_url="https://inglp.github.io/bitnami-secure-charts",
        upstream_chart_registry="registry-1.docker.io",
        upstream_chart_namespace="bitnamichartssecure",
        upstream_image_registry="registry-1.docker.io",
        upstream_image_namespace="bitnamisecure",
        target_image_prefix="bitnami-secure-",
        chart_names=chart_names,
    )


def json_lock(**payload) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def read_json(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_chart_package(path, chart_name: str, chart_version: str) -> None:
    payload = f"name: {chart_name}\nversion: {chart_version}\n".encode("utf-8")
    chart_yaml = tarfile.TarInfo(f"{chart_name}/Chart.yaml")
    chart_yaml.size = len(payload)
    chart_yaml.mtime = PACKAGE_MTIME
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(chart_yaml, io.BytesIO(payload))
