# Copyright © 2025–2026 Stefano Noferi & Admina contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Release workflows: test gate before publishing and pre-release handling.

The shell steps that classify a version are run here with sample refs, the
way GitHub Actions runs them (``bash -e``, outputs in ``$GITHUB_OUTPUT``).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
RELEASE_WORKFLOWS = ("release.yml", "release-core.yml", "release-docker.yml")
GATE = "./.github/workflows/ci.yml"

# (tag, is a pre-release)
VERSION_SAMPLES = [
    ("v0.13.0rc1", True),
    ("v0.13.0rc12", True),
    ("v0.13.0a1", True),
    ("v0.13.0b2", True),
    ("v0.13.0.dev1", True),
    ("v0.13.0-rc.1", True),
    ("v0.13.0-beta.1", True),
    ("v0.13.0-alpha.1", True),
    ("v0.13.0", False),
    ("v0.12.1", False),
    ("v1.0.0", False),
    ("v0.13.0.post1", False),
]


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    return workflow.get("on", workflow.get(True)) or {}


def _step(workflow: dict, job: str, step_id: str) -> dict:
    for step in workflow["jobs"][job]["steps"]:
        if step.get("id") == step_id:
            return step
    raise AssertionError(f"no step with id {step_id!r} in job {job!r}")


def _parse_outputs(text: str) -> dict[str, str]:
    outputs: dict[str, str] = {}
    lines = iter(text.splitlines())
    for line in lines:
        if "<<" in line and "=" not in line.split("<<", 1)[0]:
            name, marker = line.split("<<", 1)
            value = []
            for inner in lines:
                if inner == marker:
                    break
                value.append(inner)
            outputs[name] = "\n".join(value)
        elif "=" in line:
            name, value = line.split("=", 1)
            outputs[name] = value
    return outputs


def _run_step(step: dict, tmp_path: Path, **env: str) -> dict[str, str]:
    """Run a `run:` step with bash -e and return what it wrote to GITHUB_OUTPUT."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    script = step["run"]
    assert "${{" not in script, "the step reads its inputs from the environment"
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    run_env = {
        "PATH": os.environ.get("PATH", ""),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
        **env,
    }
    subprocess.run([bash, "-e", "-c", script], env=run_env, check=True, capture_output=True)
    return _parse_outputs(output.read_text(encoding="utf-8"))


def _tag_env(tag: str) -> dict[str, str]:
    return {"GITHUB_REF": f"refs/tags/{tag}", "GITHUB_REF_NAME": tag}


def _needs(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _upstream_jobs(jobs: dict, name: str) -> set[str]:
    seen: set[str] = set()
    todo = _needs(jobs[name])
    while todo:
        current = todo.pop()
        if current not in seen:
            seen.add(current)
            todo.extend(_needs(jobs[current]))
    return seen


def _publishes(job: dict) -> bool:
    """True for a job that publishes: PyPI, a GitHub Release, an image push."""
    if "environment" in job:
        return True
    for step in job.get("steps", []):
        uses = step.get("uses", "")
        if uses.startswith(("pypa/gh-action-pypi-publish@", "softprops/action-gh-release@")):
            return True
        if uses.startswith("docker/build-push-action@") and str(
            step.get("with", {}).get("push")
        ).lower() in ("true", "${{ true }}"):
            return True
        if "cosign sign" in step.get("run", ""):
            return True
    return False


# ── Every workflow ────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_workflow_yaml_loads(path):
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    assert workflow.get("jobs")


# ── Test gate ─────────────────────────────────────────────────────────────


def test_ci_workflow_can_be_called_as_a_gate():
    assert "workflow_call" in _triggers(_load("ci.yml"))


@pytest.mark.parametrize("name", RELEASE_WORKFLOWS)
def test_every_publish_job_needs_the_test_gate(name):
    jobs = _load(name)["jobs"]
    gates = {job_id for job_id, job in jobs.items() if job.get("uses") == GATE}
    publishing = [job_id for job_id, job in jobs.items() if _publishes(job)]

    assert gates, f"{name}: no job calls {GATE}"
    assert publishing, f"{name}: no publish job found"
    for job_id in publishing:
        assert gates & _upstream_jobs(jobs, job_id), f"{name}: {job_id} does not need the gate"


@pytest.mark.parametrize("name", RELEASE_WORKFLOWS)
def test_gate_runs_with_read_only_permissions(name):
    for job in _load(name)["jobs"].values():
        if job.get("uses") == GATE:
            assert job.get("permissions") == {"contents": "read"}


# ── GitHub Release: pre-release flag ──────────────────────────────────────


@pytest.mark.parametrize(("tag", "prerelease"), VERSION_SAMPLES)
def test_github_release_marks_prereleases(tmp_path, tag, prerelease):
    workflow = _load("release.yml")
    outputs = _run_step(_step(workflow, "github-release", "kind"), tmp_path, **_tag_env(tag))

    assert outputs["prerelease"] == ("true" if prerelease else "false")


def test_github_release_reads_the_prerelease_flag():
    steps = _load("release.yml")["jobs"]["github-release"]["steps"]
    release = next(s for s in steps if s.get("uses", "").startswith("softprops/"))

    assert release["with"]["prerelease"] == "${{ steps.kind.outputs.prerelease == 'true' }}"


# ── Published images: Dockerfiles ─────────────────────────────────────────

PUBLISHED_DOCKERFILES = ("admina/proxy/Dockerfile", "dashboard/Dockerfile")


def _instructions(path: str) -> list[str]:
    """The Dockerfile's instructions, continuation lines joined."""
    text = (REPO / path).read_text(encoding="utf-8").replace("\\\n", " ")
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@pytest.mark.parametrize("path", PUBLISHED_DOCKERFILES)
def test_published_images_pin_base_images_by_digest(path):
    instructions = _instructions(path)
    stages = {
        line.split()[-1].lower()
        for line in instructions
        if line.upper().startswith("FROM ") and " AS " in line.upper()
    }
    images = [line.split()[1] for line in instructions if line.upper().startswith("FROM ")]
    images += [
        word.split("=", 1)[1]
        for line in instructions
        if line.upper().startswith("COPY ")
        for word in line.split()
        if word.startswith("--from=")
    ]
    external = [image for image in images if image.lower() not in stages]

    assert external
    for image in external:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{path}: {image} is not pinned"


def test_proxy_image_build_stops_when_the_rust_engine_does_not_build():
    instructions = _instructions("admina/proxy/Dockerfile")
    build = [line for line in instructions if "maturin build" in line]
    install = [line for line in instructions if "/tmp/wheels/*.whl" in line and "RUN" in line]

    assert build and install
    for line in build + install:
        assert "||" not in line and "exit 0" not in line and "if " not in line, line


# ── Published images: tags, attestations, signatures ──────────────────────

OWNER = "admina-org"
REGISTRY = f"ghcr.io/{OWNER}"


def _image_outputs(tmp_path: Path, ref: str) -> dict[str, str]:
    workflow = _load("release-docker.yml")
    return _run_step(
        _step(workflow, "meta", "tags"),
        tmp_path,
        GITHUB_REF=ref,
        GITHUB_REF_NAME=ref.rsplit("/", 1)[-1],
        OWNER=OWNER,
    )


def _build_steps(workflow: dict) -> list[tuple[dict, dict]]:
    return [
        (job, step)
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]


@pytest.mark.parametrize(("tag", "prerelease"), VERSION_SAMPLES)
def test_image_tags_move_latest_only_for_final_releases(tmp_path, tag, prerelease):
    outputs = _image_outputs(tmp_path, f"refs/tags/{tag}")
    version = tag.removeprefix("v")
    latest = [] if prerelease else ["latest"]

    assert outputs["version"] == version
    assert outputs["proxy-tags"].splitlines() == [
        f"{REGISTRY}/admina-proxy:{t}" for t in [version, *latest]
    ]
    assert outputs["proxy-slim-tags"].splitlines() == [f"{REGISTRY}/admina-proxy:{version}-slim"]
    assert outputs["dashboard-tags"].splitlines() == [
        f"{REGISTRY}/admina-dashboard:{t}" for t in [version, *latest]
    ]


def test_manual_run_on_a_branch_tags_a_development_build_without_latest(tmp_path):
    outputs = _image_outputs(tmp_path, "refs/heads/main")

    assert outputs["version"] == "dev-0123456"
    assert outputs["proxy-tags"].splitlines() == [f"{REGISTRY}/admina-proxy:dev-0123456"]
    assert outputs["dashboard-tags"].splitlines() == [f"{REGISTRY}/admina-dashboard:dev-0123456"]


def test_images_are_pushed_with_sbom_and_max_provenance():
    builds = _build_steps(_load("release-docker.yml"))

    assert len(builds) == 3  # proxy, proxy slim, dashboard
    for _, step in builds:
        options = step["with"]
        assert str(options["push"]).lower() == "true"
        assert str(options["sbom"]).lower() == "true"
        assert options["provenance"] == "mode=max"
        assert "${{ needs.meta.outputs." in options["tags"]
        assert (
            "org.opencontainers.image.version=${{ needs.meta.outputs.version }}"
            in (options["labels"])
        )


def test_slim_image_is_the_slim_target_with_the_slim_tags():
    builds = _build_steps(_load("release-docker.yml"))
    slim = [step for _, step in builds if step["with"].get("target") == "slim"]

    assert len(slim) == 1
    assert slim[0]["with"]["file"] == "admina/proxy/Dockerfile"
    assert slim[0]["with"]["tags"] == "${{ needs.meta.outputs.proxy-slim-tags }}"


def test_every_pushed_image_is_signed_keylessly_by_digest(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    calls = tmp_path / "cosign-calls"
    stub = stub_dir / "cosign"
    stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{calls}"\n', encoding="utf-8")
    stub.chmod(0o755)

    builds = _build_steps(_load("release-docker.yml"))
    for job, build in builds:
        assert job["permissions"]["id-token"] == "write"
        assert any(s.get("uses", "").startswith("sigstore/cosign-installer@") for s in job["steps"])
        digest_ref = "${{ steps.%s.outputs.digest }}" % build["id"]
        signs = [s for s in job["steps"] if s.get("env", {}).get("DIGEST") == digest_ref]
        assert len(signs) == 1, f"no signing step for {build['id']}"
        sign = signs[0]
        assert "--key" not in sign["run"]

        calls.write_text("", encoding="utf-8")
        subprocess.run(
            [bash, "-e", "-c", sign["run"]],
            env={
                "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "IMAGE": f"{REGISTRY}/example",
                "DIGEST": "sha256:" + "ab" * 32,
            },
            check=True,
        )
        assert calls.read_text(encoding="utf-8").splitlines() == [
            f"sign --yes {REGISTRY}/example@sha256:{'ab' * 32}"
        ]
        assert sign["env"]["IMAGE"].startswith("ghcr.io/${{ github.repository_owner }}/admina-")


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_actions_are_pinned_by_commit_sha(path):
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    for job_id, job in workflow["jobs"].items():
        uses = [job["uses"]] if "uses" in job else []
        uses += [step["uses"] for step in job.get("steps", []) if "uses" in step]
        for action in uses:
            if action.startswith("./"):
                continue
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action), (
                f"{path.name}: job {job_id} uses {action}"
            )
