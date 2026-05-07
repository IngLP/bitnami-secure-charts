from __future__ import annotations

import pytest

from bitnami_secure_charts.cli import (
    ChartImage,
    ChartSelection,
    MirroredDependency,
    MirroredChartVersion,
    MirroredImage,
    MirrorConfig,
    SyncError,
    build_content_fingerprint,
    build_mirror_chart_version,
    build_target_tag,
    chart_lock_path,
    compute_lock_published,
    compute_mirror_version,
    dependency_closure_order,
    dependency_lock_key,
    find_repository_mirror,
    inspect_image,
    parse_chart_images,
    parse_env,
    patch_chart_yaml,
    patch_values_yaml,
    require_env,
    resolve_mirrored_dependencies,
    should_publish_chart,
    strip_tag,
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
                    repository="oci://registry-1.docker.io/inglp",
                    upstream_version="2.39.0",
                    version="2.39.0-inglp.r0",
                )
            ],
        )

        assert chart_yaml["version"] == "25.5.2-inglp.r0"
        assert chart_yaml["dependencies"] == [
            {
                "name": "common",
                "repository": "oci://registry-1.docker.io/inglp",
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


class TestPublishState:
    def test_dry_sync_new_content_marks_lock_unpublished(self) -> None:
        previous_lock = {
            "published": True,
        }

        assert should_publish_chart(push=False, content_changed=True, previous_lock=previous_lock) is False
        assert compute_lock_published(push=False, content_changed=True, previous_lock=previous_lock) is False

    def test_push_after_dry_sync_publishes_even_when_fingerprint_matches(self) -> None:
        previous_lock = {
            "published": False,
        }

        assert should_publish_chart(push=True, content_changed=False, previous_lock=previous_lock) is True
        assert compute_lock_published(push=True, content_changed=False, previous_lock=previous_lock) is True

    def test_push_skips_when_same_content_was_already_published(self) -> None:
        previous_lock = {
            "published": True,
        }

        assert should_publish_chart(push=True, content_changed=False, previous_lock=previous_lock) is False
        assert compute_lock_published(push=True, content_changed=False, previous_lock=previous_lock) is True


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
        repository="oci://registry-1.docker.io/inglp",
        upstream_version=upstream_version,
        version=version,
    )
