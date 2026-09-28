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

"""The directory of the filesystem forensic store in the containers.

The Docker Compose stack keeps ``FORENSIC_BASE_DIR`` of the proxy on the
named volume ``forensic-data``, so the records and the chain state outlive
the container. Both proxy images create that directory before handing
``/app`` to the non-root ``admina`` user, so a new volume mounted there
starts owned by that user.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
FORENSIC_DIR = "/app/.admina/forensic"


def _environment(service: dict) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    return dict(item.split("=", 1) for item in env)


def test_the_compose_proxy_keeps_its_forensic_directory_on_a_named_volume():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    proxy = compose["services"]["proxy"]
    env = _environment(proxy)

    assert env["FORENSIC_BACKEND"] == "filesystem"
    assert env["FORENSIC_BASE_DIR"] == FORENSIC_DIR
    assert f"forensic-data:{FORENSIC_DIR}" in proxy.get("volumes", [])
    assert "forensic-data" in compose["volumes"]


def _stages(path: str) -> dict[str, list[str]]:
    """The instructions of each named stage of the Dockerfile at *path*,
    continuation lines joined."""
    text = (REPO / path).read_text(encoding="utf-8").replace("\\\n", " ")
    stages: dict[str, list[str]] = {}
    current: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("FROM "):
            current = stages.setdefault(line.split()[-1].lower(), [])
        current.append(line)
    return stages


@pytest.mark.parametrize("target", ["slim", "full"])
def test_the_proxy_images_create_the_forensic_directory_for_the_proxy_user(target):
    stages = _stages("admina/proxy/Dockerfile")
    instructions = stages[target]
    assert instructions[0].split()[1] == "runtime"
    steps = stages["runtime"] + instructions

    chown = next(i for i, line in enumerate(steps) if "chown -R admina:admina /app" in line)
    mkdir = next(i for i, line in enumerate(steps) if f"mkdir -p {FORENSIC_DIR}" in line)
    user = next(i for i, line in enumerate(steps) if line == "USER admina")

    assert mkdir <= chown < user
    if mkdir == chown:
        line = steps[chown]
        assert line.index(f"mkdir -p {FORENSIC_DIR}") < line.index("chown -R admina:admina /app")
