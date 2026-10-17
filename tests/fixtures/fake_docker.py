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

"""A stand-in for the docker CLI, for the DockerSandbox tests that run no
engine. Each call is appended as a JSON line to $FAKE_DOCKER_LOG;
$FAKE_DOCKER_MODE selects a failure (noimage, norun, notar, slow, noinfo,
nocollect, oom) or none."""

import io
import json
import os
import sys
import tarfile
import time

args = sys.argv[1:]
mode = os.environ.get("FAKE_DOCKER_MODE", "")
with open(os.environ["FAKE_DOCKER_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\n")


def done(code=0, out=b"", err=b""):
    sys.stdout.buffer.write(out)
    sys.stderr.buffer.write(err)
    sys.exit(code)


command = args[0]
if command == "image":
    if mode == "noimage":
        done(1, err=b"Error: No such image")
    done(0, b'["python@sha256:feed"]|sha256:1d\n')
if command == "run":
    if mode == "norun":
        done(125, err=b"docker: Error response from daemon: unknown runtime")
    done(0, b"c0ffee\n")
if command == "exec":
    if "tar" in args and "-x" in args:
        sys.stdin.buffer.read()
        done(2 if mode == "notar" else 0, err=b"tar: error" if mode == "notar" else b"")
    if "tar" in args and "-c" in args:
        if mode == "nocollect":
            done(1, err=b"OCI runtime exec failed: resource temporarily unavailable")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in (("out/r.txt", b"result"), ("../escape.txt", b"x")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("out/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
        done(0, buffer.getvalue())
    if mode == "slow":
        time.sleep(30)
    stdin = sys.stdin.buffer.read() if "-i" in args else b""
    done(3, b"x" * 100 + stdin, b"warning\n")
if command == "inspect":
    if "{{.State.OOMKilled}}" in args:
        done(0, b"true\n" if mode == "oom" else b"false\n")
    done(0, b"/admina-sbx-old 1\n/admina-sbx-new 99999999999\n/admina-sbx-bad x\n")
if command == "info":
    if mode == "noinfo":
        done(1, err=b"Cannot connect to the Docker daemon")
    done(0, b'{"io.containerd.runc.v2":{},"runc":{}}\n')
if command == "ps":
    done(0, b"aaa\nbbb\nccc\n")
done(0)
