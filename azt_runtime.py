"""Read-only prerequisites for the planned Linux runtime; no workload launcher.

Presence of a binary or cgroup controller is not evidence of an effective
execution boundary. No probe executes a discovered program or contacts a daemon.
"""
import os
import platform
import shutil


DOCTOR_SCHEMA = "azt.runtime-doctor.v1"
REQUIRED_CONTROLLERS = ("cpu", "memory", "pids")
REQUIRED_CONTROLS = (
    "mount_isolation", "network_isolation", "descendant_isolation",
    "disposable_workspace", "environment_allowlist", "authority_isolation",
    "cpu_limit", "memory_limit", "process_limit", "deadline",
    "output_limit", "storage_limit", "external_stop", "controller_death_cleanup",
)


def _read_controllers():
    """Read only a bounded kernel interface, never a path supplied by the target."""
    try:
        with open("/sys/fs/cgroup/cgroup.controllers", encoding="ascii") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            return None
        return sorted(set(data.split()))
    except (OSError, UnicodeError):
        return None


def runtime_doctor(backend="bubblewrap"):
    """Return prerequisite observations, always with runtime_ready=False.

    Lookups use the OS default executable path rather than the workload's PATH.
    Returned booleans establish presence only. In particular, root cgroup
    controller visibility says nothing about delegation to the current user.
    """
    system = platform.system()
    report = {
        "schema": DOCTOR_SCHEMA,
        "platform": system,
        "backend": "bubblewrap" if backend == "bubblewrap" else "unsupported",
        "backend_version": None,
        "runtime_ready": False,
        "scope_of_observation": "read-only prerequisite presence; no execution or isolation test",
        "checks": [],
        "controls": {name: "not_verified" for name in REQUIRED_CONTROLS},
        "limitations": [
            "This legacy bubblewrap diagnostic does not assess the separate Docker research or FS-001 profiles.",
            "Executable presence does not establish its version, provenance, or behavior.",
            "Controller visibility does not establish cgroup delegation or effective limits.",
            "This diagnostic launches no process and grants no runtime authority. See research --help for the separate experimental profile.",
        ],
    }
    if backend != "bubblewrap":
        report["status"] = "unsupported_backend"
        return report
    if system != "Linux":
        report["status"] = "unsupported_platform"
        report["checks"].append({"name": "linux", "status": "missing"})
        return report
    report["checks"].append({"name": "linux", "status": "present"})
    for executable in ("bwrap", "systemd-run"):
        present = shutil.which(executable, path=os.defpath) is not None
        report["checks"].append({
            "name": executable,
            "status": "present" if present else "missing",
        })
    controllers = _read_controllers()
    for controller in REQUIRED_CONTROLLERS:
        status = "unreadable" if controllers is None else (
            "present" if controller in controllers else "missing")
        report["checks"].append({"name": "cgroup_v2." + controller, "status": status})
    if any(check["status"] == "missing" for check in report["checks"][:3]):
        report["status"] = "missing_dependency"
    elif any(check["status"] != "present" for check in report["checks"][3:]):
        report["status"] = "missing_control"
    else:
        report["status"] = "integration_unverified"
    return report


def doctor_exit_code(report):
    """No report from this prerequisite-only implementation authorizes execution."""
    return 2
