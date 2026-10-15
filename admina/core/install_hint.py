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


"""The install command that Admina's messages suggest for a missing package.

uv first, pip as the alternative: ``uv pip install 'admina[proxy]' (or pip
install 'admina[proxy]')``. ``uv pip install`` works in any virtual
environment, also one that uv created without pip.
"""

from __future__ import annotations


def install_hint(spec: str, *, upgrade: bool = False) -> str:
    """The commands that install *spec* with uv and with pip; a spec with
    extras (``admina[proxy]``) is quoted for the shell."""
    target = f"'{spec}'" if "[" in spec else spec
    if upgrade:
        target += " --upgrade"
    return f"uv pip install {target} (or pip install {target})"
