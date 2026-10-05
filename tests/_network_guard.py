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

"""A guard that refuses network access — not a test module itself.

:func:`install` replaces the name lookups (``getaddrinfo``,
``gethostbyname``, …) and the outgoing connections (``socket.connect``,
``connect_ex``, ``create_connection``) of the :mod:`socket` module: each call
is recorded and raises ``OSError``. Unix-domain sockets and socket pairs
(event loops use them) still work. The ``no_network`` fixture of
``conftest.py`` installs it for one test; a child interpreter installs it
with ``_network_guard.install()``.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from typing import Any

_LOOKUPS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr")


def install(set_attribute: Callable[[Any, str, Any], None] = setattr) -> list[str]:
    """Refuse network access from now on; return the list where every
    attempt is recorded. *set_attribute* replaces each function (default
    :func:`setattr`; pass ``monkeypatch.setattr`` to undo it after a test)."""
    attempts: list[str] = []

    def refuse(what: str) -> None:
        attempts.append(what)
        raise OSError(f"network access refused by the test guard: {what}")

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def connect(sock: socket.socket, address: Any) -> None:
        if sock.family == socket.AF_UNIX:
            return real_connect(sock, address)
        refuse(f"connect {address!r}")

    def connect_ex(sock: socket.socket, address: Any) -> int:
        if sock.family == socket.AF_UNIX:
            return real_connect_ex(sock, address)
        refuse(f"connect_ex {address!r}")
        return 1  # not reached

    def lookup(name: str) -> Callable[..., Any]:
        def refused(host: Any, *args: Any, **kwargs: Any) -> Any:
            refuse(f"{name} {host!r}")

        return refused

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        refuse(f"create_connection {address!r}")

    set_attribute(socket.socket, "connect", connect)
    set_attribute(socket.socket, "connect_ex", connect_ex)
    for name in _LOOKUPS:
        set_attribute(socket, name, lookup(name))
    set_attribute(socket, "create_connection", create_connection)
    return attempts
