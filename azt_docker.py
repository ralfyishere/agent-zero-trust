"""One bounded synthetic Docker profile. Never executes Compose commands/hooks.

Only a local Unix daemon is accepted; images must already exist. No pulls,
builds, privileged containers, host namespaces, sockets or writable host mounts.
"""
import io
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import tarfile
import time

from azt_intake import IntakeError
from azt_safety_pack import KEEPER, WORKLOAD


class BackendBlocked(IntakeError):
    pass


class ExecutionFailed(IntakeError):
    pass


def bounded_command(argv, timeout=10, limit=65536):
    """Cap combined pipes in memory; no stdin or sensitive inherited env."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, close_fds=True,
                            start_new_session=True)
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ExecutionFailed("backend command deadline exceeded")
                for event, _ in selector.select(min(left, 0.1)):
                    raw = os.read(event.fileobj.fileno(), 4096)
                    if not raw:
                        selector.unregister(event.fileobj)
                    else:
                        chunks[event.data].extend(raw)
                        if sum(map(len, chunks.values())) > limit:
                            raise ExecutionFailed("backend output limit exceeded")
            proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return proc.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"])
    finally:
        if proc.poll() is None:
            # Only the test-owned Docker CLI group. The container has a separate
            # deadline and the caller performs daemon cleanup even on failure.
            import signal
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def docker_binary():
    for candidate in ("/usr/bin/docker", "/usr/local/bin/docker", "/opt/homebrew/bin/docker"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


class Docker:
    def __init__(self, endpoint, control_dir):
        if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
            raise BackendBlocked("only an explicit local Unix Docker endpoint is supported")
        path = endpoint[7:]
        if any(c in path for c in "\n\r\x00") or ".." in Path(path).parts:
            raise BackendBlocked("invalid local Docker endpoint")
        self.endpoint = endpoint
        self.binary = docker_binary()
        self.control_dir = Path(control_dir)
        self.config_dir = self.control_dir / "docker-client"
        self.config_dir.mkdir(mode=0o700)
        self.prefix = ([self.binary, "--config", str(self.config_dir), "--host", endpoint]
                       if self.binary else [])

    def command(self, *args, timeout=10, limit=65536, allow_error=False):
        if not self.binary:
            raise BackendBlocked("Docker client is not installed at a supported system path")
        code, out, err = bounded_command(self.prefix + list(args), timeout, limit)
        if code and not allow_error:
            # Docker errors can include host paths. Keep bounded diagnostics local
            # and expose a category rather than raw daemon output in exports.
            raise ExecutionFailed("Docker operation failed: " + args[0])
        return code, out, err

    def preflight(self, image):
        result = {"backend": "docker", "client_version": None, "server_version": None,
                  "host_platform": platform.system(), "supported_host": "Linux",
                  "transport": "local-unix", "status": "blocked", "reason": None,
                  "image_id": None, "runtime_trials": 0}
        if not self.binary:
            result["reason"] = "missing_client"
            return result
        code, out, _ = self.command("--version", allow_error=True)
        match = re.search(rb"Docker version ([0-9.]+)", out)
        result["client_version"] = match.group(1).decode() if match else None
        try:
            metadata = os.stat(self.endpoint[7:])
        except FileNotFoundError:
            result["reason"] = "local_service_unavailable"
            return result
        except PermissionError:
            result["reason"] = "local_service_permission_required"
            return result
        if not stat.S_ISSOCK(metadata.st_mode):
            result["reason"] = "endpoint_not_a_socket"
            return result
        code, out, err = self.command("version", "--format", "{{json .Server}}", allow_error=True)
        if code:
            result["reason"] = ("local_service_permission_required" if b"permission denied" in err.lower()
                                else "local_service_unavailable")
            return result
        server = json.loads(out)
        result["server_version"] = server.get("Version")
        if platform.system() != "Linux" or server.get("Os") != "linux":
            result["reason"] = "unsupported_platform_native_linux_required"
            return result
        if int(server["Version"].split(".")[0]) < 25:
            result["reason"] = "unsupported_docker_version_requires_25_or_newer"
            return result
        _, out, _ = self.command("info", "--format", "{{json .}}")
        info = json.loads(out)
        controls = ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")
        if (info.get("CgroupVersion") != "2" or not all(info.get(k) is True for k in controls)
                or "name=seccomp,profile=builtin" not in info.get("SecurityOptions", [])):
            result["reason"] = "required_cgroup_v2_or_seccomp_control_unavailable"
            return result
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}", image):
            raise BackendBlocked("invalid approved image reference")
        code, out, _ = self.command("image", "inspect", image, "--format", "{{json .}}", allow_error=True)
        if code:
            result["reason"] = "approved_image_not_preloaded"
            return result
        image_data = json.loads(out)
        image_id = image_data.get("Id", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or image_data.get("Os") != "linux":
            result["reason"] = "unsupported_image"
            return result
        # Image-declared anonymous volumes would add unbounded writable storage.
        if image_data.get("Config", {}).get("Volumes"):
            result["reason"] = "image_declares_unsupported_volumes"
            return result
        result.update(status="available", reason=None, image_id=image_id,
                      image_repo_digests=image_data.get("RepoDigests", []),
                      cgroup_version="2", security_options=[s for s in info["SecurityOptions"] if "seccomp" in s])
        return result

    def create_args(self, name, image_id, pack_dir, project_dir, mounts):
        args = ["create", "--name", name, "--label", "org.azt.pack=AZT-FS-001-v1",
                "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges=true", "--cgroupns", "private",
                "--ipc", "private", "--init", "--user", "0:0", "--restart", "no", "--no-healthcheck",
                "--cpus", "0.5", "--memory", "96m", "--memory-swap", "96m", "--pids-limit", "32",
                "--ulimit", "fsize=1048576:1048576", "--ulimit", "nofile=64:64",
                "--shm-size", "1m", "--log-driver", "none", "--stop-timeout", "1",
                "--tmpfs", "/workspace:rw,nosuid,nodev,noexec,size=4m,uid=65532,gid=65532,mode=0700",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=4m,mode=1777",
                "--mount", "type=bind,src=%s,dst=/azt-pack,readonly,bind-propagation=rprivate" % pack_dir,
                "--mount", "type=bind,src=%s,dst=/input,readonly,bind-propagation=rprivate" % project_dir]
        for source, target, read_only in mounts:
            if not read_only:
                raise BackendBlocked("additional writable host mounts are not supported in this pack")
            if any(c in str(source) + target for c in ",\n\r"):
                raise BackendBlocked("mount path contains unsupported separators")
            args.extend(["--mount", "type=bind,src=%s,dst=%s,readonly,bind-propagation=rprivate" % (source, target)])
        args.extend(["--entrypoint", "/usr/bin/env", image_id, "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                     "/usr/local/bin/python3", "-I", "/azt-pack/keeper.py"])
        return args

    def inspect_controls(self, name, expected_mounts):
        _, raw, _ = self.command("inspect", name, "--format", "{{json .}}")
        cfg = json.loads(raw)
        h = cfg["HostConfig"]
        if cfg.get("Config", {}).get("Healthcheck", {}).get("Test") != ["NONE"]:
            raise ExecutionFailed("image healthcheck was not disabled")
        required = {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                    "NanoCpus": 500000000, "Memory": 100663296, "MemorySwap": 100663296,
                    "PidsLimit": 32, "CgroupnsMode": "private", "IpcMode": "private", "Init": True,
                    "ShmSize": 1048576}
        if any(h.get(k) != v for k, v in required.items()):
            raise ExecutionFailed("required backend control was not accepted")
        if (h.get("CapDrop") != ["ALL"] or h.get("CapAdd") or h.get("PidMode") not in ("", None)
                or "no-new-privileges=true" not in h.get("SecurityOpt", [])
                or h.get("LogConfig", {}).get("Type") != "none"
                or h.get("RestartPolicy", {}).get("Name") != "no"):
            raise ExecutionFailed("capability, namespace, logging or lifecycle control mismatch")
        actual = {(m["Source"], m["Destination"], m["RW"]) for m in cfg["Mounts"] if m["Type"] == "bind"}
        expected = {(str(s), t, False) for s, t in expected_mounts}
        if actual != expected or any(m["Type"] not in ("bind", "tmpfs") for m in cfg["Mounts"]):
            raise ExecutionFailed("effective mount set differs from synthetic plan")
        if set(h.get("Tmpfs", {})) != {"/workspace", "/tmp"}:
            raise ExecutionFailed("writable storage scope mismatch")
        for options in h["Tmpfs"].values():
            if not all(option in options.split(",") for option in ("size=4m", "nosuid", "nodev", "noexec")):
                raise ExecutionFailed("required tmpfs size/flags not accepted")
        limits = {u["Name"]: (u["Soft"], u["Hard"]) for u in h.get("Ulimits", [])}
        if limits.get("fsize") != (1048576, 1048576) or limits.get("nofile") != (64, 64):
            raise ExecutionFailed("required file/output limits not accepted")
        return {"configured_and_read_back": required, "all_capabilities_dropped": True,
                "no_new_privileges": True, "host_mounts": "synthetic read-only inputs only",
                "writable_storage": {"workspace_bytes": 4194304, "tmp_bytes": 4194304, "shm_bytes": 1048576},
                "deadline_seconds": 20, "scope": "Docker configuration readback; only selected file read is exercised"}

    def trial(self, name, image_id, pack_dir, project_dir, mounts, challenge, probe_path):
        created = False
        record = {"session_id": name, "status": "failed", "workload_claim": None, "cleanup": "not_started"}
        try:
            # Name is evaluator-generated, so removal after a timed-out create is
            # confined to this unique test session even if creation did succeed.
            created = True
            self.command(*self.create_args(name, image_id, pack_dir, project_dir, mounts))
            record["controls"] = self.inspect_controls(name, [(pack_dir, "/azt-pack"), (project_dir, "/input")]
                                                       + [(s, t) for s, t, _ in mounts])
            self.command("start", name)
            _, stdout, _ = self.command("exec", "--user", "65532:65532", name,
                                       "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                                       "/usr/local/bin/python3", "-I", "/azt-pack/workload.py",
                                       challenge, probe_path, timeout=8, limit=8192)
            record["workload_claim"] = json.loads(stdout)
            # Copy the bounded result while the tmpfs is mounted. Never extract
            # an archive into the host filesystem or follow a workload symlink.
            _, archived, _ = self.command("cp", name + ":/workspace/task.py", "-", timeout=4, limit=16384)
            record["result_bytes"] = result_from_tar(archived)
            record["status"] = "executed"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, IntakeError, tarfile.TarError):
            record["error"] = "trial failed before independent verification; no denial credited"
        finally:
            if created:
                try:
                    self.command("rm", "--force", name, timeout=5)
                    # Successful Docker rm means this named container and its
                    # processes are removed; broader descendant tests are separate.
                    record["cleanup"] = "removed"
                except (OSError, ValueError, subprocess.SubprocessError):
                    record["cleanup"] = "failed"
                    record["status"] = "failed"
        return record


def result_from_tar(raw):
    # Docker cp emits uncompressed tar. Preflight every physical header BEFORE
    # letting tarfile interpret extensions; compressed or sparse archives fail.
    if len(raw) > 16384 or len(raw) < 1024 or len(raw) % 512:
        raise ExecutionFailed("invalid bounded result archive")
    offset, headers = 0, 0
    while offset + 512 <= len(raw) and any(raw[offset:offset + 512]):
        header = tarfile.TarInfo.frombuf(raw[offset:offset + 512], "utf-8", "strict")
        headers += 1
        if (headers > 3 or header.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.XHDTYPE)
                or header.size < 0 or header.size > 4096):
            raise ExecutionFailed("unsupported result archive header")
        if header.type == tarfile.XHDTYPE and b"GNU.sparse" in raw[offset + 512:offset + 512 + header.size]:
            raise ExecutionFailed("sparse result archive is unsupported")
        offset += 512 + ((header.size + 511) // 512) * 512
    if offset > len(raw) - 1024 or any(raw[offset:]):
        raise ExecutionFailed("invalid result archive terminator")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != 1 or members[0].name != "task.py" or not members[0].isfile() or members[0].size > 4096:
            raise ExecutionFailed("unsafe or oversized workload result")
        stream = archive.extractfile(members[0])
        return stream.read(4097)
