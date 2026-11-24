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

"""Network destinations named by a shell command string.

The command is split the way a POSIX shell splits it, so quoting does not hide
a host (``"https://e""xample.org"``). Three shapes are read:

- a URL with a scheme, anywhere in the command;
- ``user@host:path``, anywhere in the command, and ``host:path`` as an
  argument of ``scp`` or ``rsync``;
- the target of a network client (``curl``, ``wget``, ``ssh``, ``nc``, ...)
  in command position, with or without a wrapper such as ``sudo``.

A host built when the command runs (``$HOST``, ``$(...)``, backticks) cannot be
read: the result says so with ``unresolved``. Nothing is executed or resolved,
and a program that assembles its destination from parts is not covered.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["CommandDestinations", "command_destinations"]

# The lookbehind gives one attempt per run of scheme characters, so a long run
# without "://" is read once (see "Pattern timing" in the README).
_URL_RX = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*+://[^\s'\"<>]*+")
_USER_AT_HOST_RX = re.compile(r"^[\w.-]++@([A-Za-z0-9.-]++):")
_HOST_PATH_RX = re.compile(r"^([A-Za-z0-9.-]++):")
_HOST_RX = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*+(?<=[A-Za-z0-9]))?$")
_ASSIGNMENT_RX = re.compile(r"^[A-Za-z_]\w*+=")

_OPERATOR_CHARS = frozenset("();<>|&")
_RUNTIME_CHARS = frozenset("$`")
_PATH_START = ("/", ".", "~", "@")
_MAX_HOST_LENGTH = 253
_SCRIPT_FLAGS = frozenset({"-c", "-lc", "-ic"})
_MAX_SCRIPT_DEPTH = 3

# Commands that run the command after them.
_WRAPPERS = frozenset(
    {"sudo", "env", "nohup", "time", "timeout", "exec", "command", "nice", "xargs"}
)
# Clients with one destination: what follows it goes to the remote end.
_SINGLE_TARGET = frozenset({"ssh", "sftp", "ftp", "telnet", "nc", "ncat", "netcat"})
_MANY_TARGETS = frozenset({"curl", "wget", "http", "https"})
_COPY_CLIENTS = frozenset({"scp", "rsync"})

_CURL_VALUES = "-o -d -H -A -u -T -F -b -c -K -w -X -e -m -D -r"
_CURL_LONG_VALUES = (
    "--output --data --data-raw --data-binary --data-urlencode --header --user-agent --user "
    "--upload-file --form --cookie --cookie-jar --config --write-out --request --referer "
    "--max-time --connect-timeout --retry --dump-header --range"
)
# Options whose next argument is not a destination.
_VALUE_FLAGS = {
    "curl": frozenset(f"{_CURL_VALUES} {_CURL_LONG_VALUES}".split()),
    "wget": frozenset(
        "-O -o -P -U -T -t --output-document --directory-prefix --user-agent".split()
    ),
    "ssh": frozenset("-i -l -p -F -o -L -R -D -E -c -m".split()),
    "sftp": frozenset("-i -P -F -o -b".split()),
    "scp": frozenset("-i -P -F -o -l -c".split()),
    "rsync": frozenset("-e --rsh --exclude --include --rsync-path".split()),
    "nc": frozenset("-w -p -s -i".split()),
    "ncat": frozenset("-w -p -s -i".split()),
    "netcat": frozenset("-w -p -s -i".split()),
}


@dataclass
class CommandDestinations:
    """The result of :func:`command_destinations`.

    Attributes:
        hosts: The hosts named by the command, lowercase, in order of
            appearance, each once.
        unresolved: A destination is built when the command runs.
    """

    hosts: list[str] = field(default_factory=list)
    unresolved: bool = False

    def add(self, host: str) -> None:
        host = host.lower()
        if host not in self.hosts:
            self.hosts.append(host)


def command_destinations(command: str) -> CommandDestinations:
    """The destinations *command* names; see the module docstring."""
    found = CommandDestinations()
    _read_script(command, found, 0)
    return found


def _read_script(script: str, found: CommandDestinations, depth: int) -> None:
    for line in script.replace("\\\n", " ").splitlines():
        _read_line(line, found, depth)


def _tokens(line: str) -> Iterator[str]:
    """The words and operators of *line*; on unbalanced quotes, its words."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return iter(list(lexer))
    except ValueError:
        return iter(line.split())


def _read_line(line: str, found: CommandDestinations, depth: int) -> None:
    client = None
    at_command = True
    skip_value = False
    script_next = False
    for token in _tokens(line):
        if token.startswith("#"):
            return
        if set(token) <= _OPERATOR_CHARS:
            client, at_command, skip_value, script_next = None, True, False, False
            continue
        if script_next:
            script_next = False
            if depth < _MAX_SCRIPT_DEPTH:
                _read_script(token, found, depth + 1)
                continue
        script_next = token in _SCRIPT_FLAGS
        urls = _read_urls(token, found)
        match = _USER_AT_HOST_RX.match(token)
        if match:
            found.add(match.group(1))
        if at_command:
            name = token.rsplit("/", 1)[-1]
            if name in _SINGLE_TARGET or name in _MANY_TARGETS or name in _COPY_CLIENTS:
                client, at_command = name, False
            elif not (name in _WRAPPERS or token[0] == "-" or token.isdigit()) and (
                not _ASSIGNMENT_RX.match(token)
            ):
                at_command = False
            continue
        if client is None or urls or match:
            if client in _SINGLE_TARGET and (urls or match):
                client = None
            skip_value = False
            continue
        if skip_value:
            skip_value = False
            continue
        if token[0] == "-":
            skip_value = _takes_value(client, token)
            continue
        if client in _COPY_CLIENTS:
            copy_target = _HOST_PATH_RX.match(token)
            if copy_target and not token.startswith(_PATH_START):
                found.add(copy_target.group(1))
            continue
        if _read_target(token, found) and client in _SINGLE_TARGET:
            client = None


def _takes_value(client: str, flag: str) -> bool:
    flags = _VALUE_FLAGS.get(client, frozenset())
    if flag in flags:
        return True
    # A cluster of short options: the last one takes the value (-sSo FILE).
    return not flag.startswith("--") and f"-{flag[-1]}" in flags


def _read_urls(token: str, found: CommandDestinations) -> bool:
    """Add the hosts of the URLs in *token*; True when it holds one."""
    if "://" not in token:
        return False
    seen = False
    for match in _URL_RX.finditer(token):
        seen = True
        url = match.group()
        authority = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if not authority:
            continue  # file:///path
        if _RUNTIME_CHARS.intersection(authority):
            found.unresolved = True
            continue
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            found.add(host)
        else:
            found.unresolved = True
    return seen


def _read_target(token: str, found: CommandDestinations) -> bool:
    """Read *token* as the destination of a network client; True when it is one."""
    if _RUNTIME_CHARS.intersection(token):
        found.unresolved = True
        return True
    if token.startswith(_PATH_START) or token.isdigit():
        return False
    host = token.rsplit("@", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if not host or len(host) > _MAX_HOST_LENGTH or not _HOST_RX.match(host):
        return False
    found.add(host)
    return True
