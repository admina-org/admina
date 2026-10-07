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

# The last release of admina-framework: the code is published as admina
# since 0.14.0. Installing this source distribution stops with the commands
# to switch, before pip or uv change the installed packages.

raise SystemExit(
    "\n\nadmina-framework is now published as admina (since 0.14.0).\n"
    "Run:  pip uninstall -y admina admina-framework && pip install admina\n"
    "Extras keep their names: admina-framework[proxy] is admina[proxy].\n"
    "See https://github.com/admina-org/admina/blob/main/docs/guides/package-name.md\n"
)
