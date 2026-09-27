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
