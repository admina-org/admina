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

"""Secrets read from files (the ``<SETTING>_FILE`` convention).

A secret setting ``X`` can be given directly or as ``X_FILE``, the path of
a file that holds it (a Docker or Kubernetes secret, for example). The
file is read once, when the setting is resolved; one trailing newline
(``\\n`` or ``\\r\\n``) is removed. A missing, unreadable, non-UTF-8 or
empty file is an error, and so is setting both ``X`` and ``X_FILE``.

Error messages name the setting and the file path, never the content.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

__all__ = ["SecretFileError", "read_secret_file", "resolve_secret", "secret_from_env"]


class SecretFileError(ValueError):
    """A secret setting cannot be resolved (the message never holds the secret)."""


def read_secret_file(path: str | os.PathLike[str], *, setting: str) -> str:
    """Return the secret stored in *path*, without one trailing newline.

    Args:
        path: File holding the secret.
        setting: Name of the setting that points at the file, used in
            error messages (for example ``"ADMINA_API_KEY_FILE"``).

    Raises:
        SecretFileError: The file cannot be read, is not UTF-8 text or
            holds nothing but a newline.
    """
    shown = os.fspath(path)
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise SecretFileError(f"{setting}: cannot read {shown!r} ({reason})") from None
    # Decode outside an ``except`` block so that no exception carrying the
    # raw bytes is chained to the error.
    value = _decode(raw)
    if value is None:
        raise SecretFileError(f"{setting}: {shown!r} is not UTF-8 text")
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not value:
        raise SecretFileError(f"{setting}: {shown!r} is empty")
    return value


def resolve_secret(value: str | None, file_path: str | None, *, setting: str) -> str | None:
    """Return the secret of *setting* given directly or through ``<setting>_FILE``.

    Args:
        value: Value of ``<setting>``; empty or None means unset.
        file_path: Value of ``<setting>_FILE``; empty or None means unset.
        setting: Name of the setting, used in error messages.

    Returns:
        The secret, or None when neither is set.

    Raises:
        SecretFileError: Both are set, or the file cannot be used
            (see :func:`read_secret_file`).
    """
    if value and file_path:
        raise SecretFileError(f"{setting} and {setting}_FILE are both set; set only one of them")
    if file_path:
        return read_secret_file(file_path, setting=f"{setting}_FILE")
    return value or None


def secret_from_env(setting: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Return the secret of the environment variable *setting* or of the
    file named by ``<setting>_FILE`` (see :func:`resolve_secret`).

    Args:
        setting: Name of the variable, for example ``"ADMINA_FORENSIC_STATE_KEY"``.
        environ: Variables to read; defaults to ``os.environ``.
    """
    env = os.environ if environ is None else environ
    return resolve_secret(env.get(setting), env.get(f"{setting}_FILE"), setting=setting)


def _decode(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
