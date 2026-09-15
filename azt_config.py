"""Strict, non-executing adapter for one-service Compose JSON bind declarations.

Resolution here is lexical: no daemon, host mount, hook, or repository code is
executed. Only the bundled regression harness can supply execution evidence.
"""
import copy
import difflib
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from azt_intake import IntakeError, json_object, open_absolute, read_fd

ADAPTER_VERSION = "compose-json-bind-v1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_MOUNTS = 32


class ConfigError(IntakeError):
    pass


@dataclass
class Config:
    path: Path
    raw: bytes
    document: dict
    service: str
    mounts: list
    sha256: str


def _text(value, label):
    if (not isinstance(value, str) or not value or len(value) > 1024
            or any(c in value for c in "$~\\")
            or any(ord(c) < 32 or ord(c) > 126 for c in value)):
        raise ConfigError(label + " must be bounded literal ASCII without interpolation")
    return value


def _absolute(value, label):
    _text(value, label)
    if (not value.startswith("/") or value.startswith("//")
            or (value != "/" and any(p in ("", ".", "..") for p in value[1:].split("/")))):
        raise ConfigError(label + " must be canonical absolute POSIX path")
    return value


def _source(value, parent):
    _text(value, "bind source")
    if value.startswith("/"):
        return _absolute(value, "bind source")
    if (not value.startswith("./") or
            any(p in ("", ".", "..") for p in value[2:].split("/"))):
        raise ConfigError("bind source must be absolute or canonical ./relative path")
    return str(parent / value[2:])


def _contains(parent, child):
    return PurePosixPath(parent) == PurePosixPath(child) or PurePosixPath(parent) in PurePosixPath(child).parents


def _parse(raw, path, service):
    if not isinstance(raw, bytes) or len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration byte limit exceeded or non-byte input")
    try:
        data = json_object(raw.decode("utf-8"))
    except (UnicodeError, IntakeError) as exc:
        raise ConfigError("configuration must be bounded unique-key UTF-8 JSON") from exc
    if not set(data) <= {"services", "name"} or "services" not in data:
        raise ConfigError("unsupported Compose layer or top-level setting")
    if not isinstance(service, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", service):
        raise ConfigError("invalid service identifier")
    if "name" in data:
        _text(data["name"], "project name")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", data["name"]):
            raise ConfigError("invalid project name")
    if not isinstance(data["services"], dict) or set(data["services"]) != {service}:
        raise ConfigError("exactly the explicitly selected service must be present")
    settings = data["services"][service]
    if (not isinstance(settings, dict) or not {"image", "volumes"} <= set(settings)
            or not set(settings) <= {"image", "working_dir", "volumes", "labels"}):
        raise ConfigError("unsupported or missing service settings")
    image = _text(settings["image"], "image")
    if any(c.isspace() for c in image):
        raise ConfigError("image cannot contain whitespace")
    if "working_dir" in settings and settings["working_dir"] != "/workspace":
        raise ConfigError("only /workspace working_dir is supported")
    if "labels" in settings:
        if not isinstance(settings["labels"], dict) or len(settings["labels"]) > 32:
            raise ConfigError("labels must be a bounded string mapping")
        for key, val in settings["labels"].items():
            _text(key, "label key")
            _text(val, "label value")
    volumes = settings["volumes"]
    if not isinstance(volumes, list) or len(volumes) > MAX_MOUNTS:
        raise ConfigError("volumes must be a bounded list of long-form bind mounts")
    mounts = []
    for index, volume in enumerate(volumes):
        if (not isinstance(volume, dict) or set(volume) != {"type", "source", "target", "read_only"}
                or volume["type"] != "bind" or type(volume["read_only"]) is not bool):
            raise ConfigError("only explicit long-form bind mounts with boolean read_only are supported")
        target = _absolute(volume["target"], "bind target")
        source = _source(volume["source"], path.parent)
        if any(_contains(m["target"], target) or _contains(target, m["target"]) for m in mounts):
            raise ConfigError("duplicate or overlapping mount targets are ambiguous")
        mounts.append({"index": index, "source": source, "declared_source": volume["source"],
                       "target": target, "read_only": volume["read_only"],
                       "provenance": "/services/" + service + "/volumes/" + str(index)})
    return Config(path, raw, data, service, mounts, hashlib.sha256(raw).hexdigest())


def parse_config(raw, path, service="worker"):
    """Parse trusted captured bytes using an explicit logical source filename.

    Used for checking generated repairs without writing a user's configuration.
    This function does not attest that the named path contains these bytes.
    """
    return _parse(raw, Path(os.path.abspath(path)), service)


def load_config(path, service="worker"):
    """Read a single explicit document, refusing symlink and special-file inputs."""
    path = Path(os.path.abspath(path))
    try:
        fd = open_absolute(path)
        try:
            raw, _ = read_fd(fd, MAX_CONFIG_BYTES)
        finally:
            os.close(fd)
    except (OSError, IntakeError) as exc:
        raise ConfigError("configuration path cannot be safely read") from exc
    return _parse(raw, path, service)


def compare_configs(baseline, candidate, protected_source):
    """Compare bind declarations; exposure means declared access, not a read."""
    protected_source = _absolute(str(protected_source), "protected source")
    if baseline.service != candidate.service:
        raise ConfigError("cannot compare different selected services")
    before = {m["target"]: m for m in baseline.mounts}
    after = {m["target"]: m for m in candidate.mounts}
    changes = []
    for target in sorted(set(before) | set(after)):
        old, new = before.get(target), after.get(target)
        keys = ("source", "read_only")
        if old and new and all(old[k] == new[k] for k in keys):
            continue
        exposes = bool(new and _contains(new["source"], protected_source))
        changes.append({"target": target, "kind": "added" if old is None else "removed" if new is None else "modified",
                        "before": old, "after": new, "declares_protected_read_access": exposes,
                        "implication": "bind declaration exposes selected protected directory, even when read-only" if exposes else "selected protected directory is not newly exposed by this change"})
    return {"schema_version": 1, "adapter": ADAPTER_VERSION,
            "service": baseline.service, "baseline_sha256": baseline.sha256,
            "candidate_sha256": candidate.sha256, "protected_source": protected_source,
            "configuration_scope": "one explicit standalone Compose JSON document; no implicit discovery or merge",
            "resolution": "lexical bind paths relative to each document; host symlinks and daemon access untested",
            "access_exercised": False, "changes": changes,
            "baseline_declares_protected_access": any(_contains(m["source"], protected_source) for m in baseline.mounts),
            "candidate_declares_protected_access": any(_contains(m["source"], protected_source) for m in candidate.mounts),
            "unknown": ["effective engine mount access", "image contents and behavior", "configuration outside explicitly supplied documents"]}


def _volume_spans(text, service):
    """Locate validated JSON array values to preserve unrelated formatting."""
    import json
    decoder = json.JSONDecoder()

    def space(i):
        while text[i].isspace():
            i += 1
        return i

    def member(i, key):
        i = space(i + 1)
        while text[i] != "}":
            name, end = decoder.raw_decode(text, i)
            start = space(space(end) + 1)
            _, end = decoder.raw_decode(text, start)
            if name == key:
                return start
            i = space(end)
            if text[i] == ",":
                i = space(i + 1)
        raise ConfigError("missing validated JSON member")

    i = member(member(member(space(0), "services"), service), "volumes")
    start = space(i + 1)
    spans = []
    while text[start] != "]":
        _, end = decoder.raw_decode(text, start)
        spans.append((start, end))
        start = space(end)
        if text[start] == ",":
            start = space(start + 1)
    return spans


def propose_repair(baseline, candidate, protected_source):
    """Restore/remove only candidate mounts newly exposing selected resource."""
    import json
    comparison = compare_configs(baseline, candidate, protected_source)
    if comparison["baseline_declares_protected_access"]:
        raise ConfigError("reviewed baseline already declares protected access")
    offending = [c for c in comparison["changes"] if c["declares_protected_read_access"]]
    text = candidate.raw.decode("utf-8")
    spans = _volume_spans(text, candidate.service)
    removed, replacement = set(), {}
    for change in offending:
        index = change["after"]["index"]
        if change["before"] is None:
            removed.add(index)
        else:
            old = copy.deepcopy(baseline.document["services"][baseline.service]["volumes"][change["before"]["index"]])
            # Keep baseline authority if configurations live in different directories.
            if old["source"].startswith("./") and baseline.path.parent != candidate.path.parent:
                old["source"] = change["before"]["source"]
            replacement[index] = json.dumps(old, ensure_ascii=True)
    # Reconstruct only the mount array interior using original item fragments.
    if spans:
        kept = [i for i in range(len(spans)) if i not in removed]
        chunks = []
        for position, index in enumerate(kept):
            if position:
                previous = kept[position - 1]
                # Preserve original separator whitespace where possible.
                separator = text[spans[previous][1]:spans[previous + 1][0]]
                chunks.append(separator)
            chunks.append(replacement.get(index, text[spans[index][0]:spans[index][1]]))
        repaired = text[:spans[0][0]] + "".join(chunks) + text[spans[-1][1]:]
    else:
        repaired = text
    checked = _parse(repaired.encode("utf-8"), candidate.path, candidate.service)
    if compare_configs(baseline, checked, protected_source)["candidate_declares_protected_access"]:
        raise ConfigError("repair could not remove declared exposure")
    return {"schema_version": 1, "adapter": ADAPTER_VERSION,
            "service": candidate.service, "protected_source": str(protected_source),
            "original_sha256": candidate.sha256, "baseline_sha256": baseline.sha256,
            "affected_indices": sorted(removed | set(replacement)),
            "status": "proposed" if offending else "no_change",
            "repaired_content": repaired,
            "repaired_sha256": checked.sha256,
            "diff": "".join(difflib.unified_diff(text.splitlines(True), repaired.splitlines(True),
                                               fromfile="candidate.compose.json", tofile="repaired.compose.json")),
            "authority": "review proposal only; no settings are written"}


def verify_repair(candidate_path, proposal, baseline, protected_source, service=None):
    """Return verified bytes for a trusted harness; never apply real settings."""
    candidate = load_config(candidate_path, service or baseline.service)
    if not isinstance(proposal, dict) or candidate.sha256 != proposal.get("original_sha256"):
        raise ConfigError("stale or invalid repair proposal")
    expected = propose_repair(baseline, candidate, protected_source)
    if proposal != expected:
        raise ConfigError("repair proposal differs from independently regenerated narrow repair")
    return expected["repaired_content"].encode("utf-8")
